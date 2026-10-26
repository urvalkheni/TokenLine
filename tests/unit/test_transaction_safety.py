import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
import pytest
from sqlalchemy import create_engine, inspect

from backend.collector.app import app
from backend.collector.db import init_db, get_session, Event, TokenReuseRecord, ScenarioExecution
from backend.correlator import TokenFamilyCorrelator, TokenStatus
from backend.database.migrations import MigrationManager


@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    app.config["TESTING"] = True

    with app.test_client() as test_client:
        test_client.environ_base = {"HTTP_AUTHORIZATION": "Bearer tokenline-admin-secret"}
        with app.app_context():
            init_db()
        yield test_client

    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass


def test_duplicate_event_submission_idempotency(client):
    """
    Submitting the exact same event sequentially returns 201 on first submission
    and 200 'event already exists' on subsequent submissions without creating duplicate records.
    """
    event = {
        "event_id": "evt-dup-100",
        "event_type": "token_issued",
        "time": "2026-08-07T12:00:00Z",
        "user_id": "user-dup",
        "token_hash": "a1b2c3d4e5f6",
        "token_family": "fam-dup-100",
        "ip_hash": "112233445566",
        "device_id": "device-dup-1",
        "result": "accepted",
        "schema_version": "1.0.0",
        "source": "demo-app",
        "is_simulation": False
    }

    res1 = client.post("/api/events", json=event)
    assert res1.status_code == 201
    assert res1.get_json().get("status") == "event persisted"

    res2 = client.post("/api/events", json=event)
    assert res2.status_code == 200
    assert res2.get_json().get("status") == "event already exists"

    # Verify database contains exactly 1 row
    db = get_session()
    try:
        rows = db.query(Event).filter(Event.event_id == "evt-dup-100").all()
        assert len(rows) == 1
    finally:
        db.close()


def test_concurrent_duplicate_event_submissions(client):
    """
    Simultaneous submissions of the same event across multiple threads return
    deterministic 200/201 responses with zero 500 errors and exactly 1 database row.
    """
    event = {
        "event_id": "evt-race-dup",
        "event_type": "token_issued",
        "time": "2026-08-07T12:05:00Z",
        "user_id": "user-race",
        "token_hash": "b2c3d4e5f6a1",
        "token_family": "fam-race",
        "ip_hash": "223344556677",
        "device_id": "device-race-1",
        "result": "accepted",
        "schema_version": "1.0.0",
        "source": "collector",
        "is_simulation": False
    }

    status_codes = []

    def submit():
        with app.test_client() as thread_client:
            thread_client.environ_base = {"HTTP_AUTHORIZATION": "Bearer tokenline-admin-secret"}
            res = thread_client.post("/api/events", json=event)
            return res.status_code

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(submit) for _ in range(6)]
        for f in as_completed(futures):
            status_codes.append(f.result())

    # All threads must succeed (either 201 for the one that persisted or 200 for duplicates)
    for code in status_codes:
        assert code in (200, 201), f"Unexpected status code {code}"
    assert 201 in status_codes
    assert status_codes.count(201) == 1

    # Exactly 1 row in the database
    db = get_session()
    try:
        rows = db.query(Event).filter(Event.event_id == "evt-race-dup").all()
        assert len(rows) == 1
    finally:
        db.close()


def test_simultaneous_refresh_token_reuse_submissions(client):
    """
    Concurrent refresh-token reuse submissions for the same rotated token
    produce consistent correlation without duplicate reuse records.
    """
    # 1. Issue initial token
    issue_event = {
        "event_id": "evt-reuse-issue",
        "event_type": "token_issued",
        "time": "2026-08-07T13:00:00Z",
        "user_id": "user-victim",
        "token_hash": "a11111111111",
        "token_family": "family-reuse-test",
        "ip_hash": "123456789abc",
        "device_id": "device-victim",
        "result": "accepted"
    }
    r_issue = client.post("/api/events", json=issue_event)
    assert r_issue.status_code == 201

    # 2. Legitimate refresh: rotates a11111111111 -> b22222222222
    refresh_event = {
        "event_id": "evt-reuse-rot",
        "event_type": "token_refreshed",
        "time": "2026-08-07T13:10:00Z",
        "user_id": "user-victim",
        "token_hash": "b22222222222",
        "parent_token_hash": "a11111111111",
        "token_family": "family-reuse-test",
        "ip_hash": "123456789abc",
        "device_id": "device-victim",
        "result": "accepted"
    }
    r_ref = client.post("/api/events", json=refresh_event)
    assert r_ref.status_code == 201

    # 3. Adversary attempts to reuse rotated a11111111111
    reuse_event = {
        "event_id": "evt-reuse-attack-1",
        "event_type": "token_refreshed",
        "time": "2026-08-07T13:20:00Z",
        "user_id": "user-victim",
        "token_hash": "c33333333333",
        "parent_token_hash": "a11111111111",
        "token_family": "family-reuse-test",
        "ip_hash": "999888777666",
        "device_id": "device-attacker",
        "result": "rejected"
    }

    # Concurrently submit reuse event 8 times across distinct client threads
    status_codes = []

    def submit_reuse():
        with app.test_client() as thread_client:
            thread_client.environ_base = {"HTTP_AUTHORIZATION": "Bearer tokenline-admin-secret"}
            res = thread_client.post("/api/events", json=reuse_event)
            return res.status_code

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(submit_reuse) for _ in range(8)]
        for f in as_completed(futures):
            status_codes.append(f.result())

    for code in status_codes:
        assert code in (200, 201), f"Unexpected status {code}"

    # Verify exactly 1 TokenReuseRecord exists in database
    db = get_session()
    try:
        reuse_rows = db.query(TokenReuseRecord).filter(
            TokenReuseRecord.token_hash == "a11111111111",
            TokenReuseRecord.attempted_event_id == "evt-reuse-attack-1"
        ).all()
        assert len(reuse_rows) == 1

        # Check API endpoint also reports exactly 1 record
        res = client.get("/api/reuse-records")
        assert res.status_code == 200
        records = [r for r in res.get_json() if r["attempted_event_id"] == "evt-reuse-attack-1"]
        assert len(records) == 1
    finally:
        db.close()


def test_duplicate_alert_and_reuse_record_prevention(client):
    """
    Subsequent re-submissions of a reuse event never create duplicate alerts or reuse records.
    """
    # Issue + Refresh
    client.post("/api/events", json={
        "event_id": "evt-dup-alert-issue",
        "event_type": "token_issued",
        "time": "2026-08-07T14:00:00Z",
        "user_id": "u-alert",
        "token_hash": "d11111111111",
        "token_family": "fam-alert-test",
        "ip_hash": "111122223333",
        "device_id": "dev-alert",
        "result": "accepted"
    })
    client.post("/api/events", json={
        "event_id": "evt-dup-alert-rot",
        "event_type": "token_refreshed",
        "time": "2026-08-07T14:05:00Z",
        "user_id": "u-alert",
        "token_hash": "d22222222222",
        "parent_token_hash": "d11111111111",
        "token_family": "fam-alert-test",
        "ip_hash": "111122223333",
        "device_id": "dev-alert",
        "result": "accepted"
    })

    attack_event = {
        "event_id": "evt-dup-alert-attack",
        "event_type": "token_refreshed",
        "time": "2026-08-07T14:10:00Z",
        "user_id": "u-alert",
        "token_hash": "d33333333333",
        "parent_token_hash": "d11111111111",
        "token_family": "fam-alert-test",
        "ip_hash": "999988887777",
        "device_id": "dev-malicious",
        "result": "rejected"
    }

    # Submit first time -> 201
    r1 = client.post("/api/events", json=attack_event)
    assert r1.status_code == 201

    # Submit second time -> 200
    r2 = client.post("/api/events", json=attack_event)
    assert r2.status_code == 200

    # Submit third time -> 200
    r3 = client.post("/api/events", json=attack_event)
    assert r3.status_code == 200

    res_reuse = client.get("/api/reuse-records")
    items = [x for x in res_reuse.get_json() if x["attempted_event_id"] == "evt-dup-alert-attack"]
    assert len(items) == 1


def test_transaction_rollback_when_correlation_fails(client, monkeypatch):
    """
    If correlation fails during event ingestion, the database event insertion
    must be rolled back atomically so no orphaned event remains.
    """
    import sys
    collector_mod = sys.modules["backend.collector.app"]

    def failing_correlate(data, db_sess):
        raise RuntimeError("Engine correlation fault simulated")

    monkeypatch.setattr(collector_mod, "process_event", failing_correlate)

    event = {
        "event_id": "evt-corr-rollback-test",
        "event_type": "token_issued",
        "time": "2026-08-07T15:00:00Z",
        "user_id": "u-rollback",
        "token_hash": "e11111111111",
        "token_family": "fam-corr-rollback",
        "ip_hash": "abcdef123456",
        "device_id": "dev-rollback",
        "result": "accepted"
    }

    res = client.post("/api/events", json=event)
    assert res.status_code == 500
    assert res.get_json().get("error") == "Correlation error"

    # Verify event was rolled back and is NOT present in database
    db = get_session()
    try:
        found = db.query(Event).filter(Event.event_id == "evt-corr-rollback-test").first()
        assert found is None, "Failed transaction was not rolled back; event was committed!"
    finally:
        db.close()


def test_scenario_execution_failure_and_partial_run_recovery(client, monkeypatch):
    """
    When a scenario fails midway, all partial events are rolled back atomically,
    and a failed ScenarioExecution record is created rather than reporting success.
    """
    import sys
    collector_mod = sys.modules["backend.collector.app"]

    # Allow event 1 to correlate, but fail on subsequent events
    call_count = {"count": 0}
    orig_process = collector_mod.process_event

    def fail_on_second(evt, db_sess):
        call_count["count"] += 1
        if call_count["count"] >= 2:
            raise RuntimeError("Midway scenario failure simulated")
        return orig_process(evt, db_sess)

    monkeypatch.setattr(collector_mod, "process_event", fail_on_second)

    res = client.post("/api/scenarios/replay/run")
    assert res.status_code == 500
    res_data = res.get_json()
    assert res_data.get("error") == "Correlation error"
    assert "execution_id" in res_data
    exec_id = res_data["execution_id"]

    # Verify zero partial events were persisted
    db = get_session()
    try:
        # Check scenario executions table
        exec_record = db.query(ScenarioExecution).filter(ScenarioExecution.id == exec_id).first()
        assert exec_record is not None
        assert exec_record.status == "failed"
        assert "Midway scenario failure simulated" in exec_record.error_message

        # Replay scenario events should NOT be left committed
        events = db.query(Event).filter(Event.source == "scenario:replay").all()
        assert len(events) == 0, "Partial scenario events were committed despite failure!"
    finally:
        db.close()

    # Verify API executions endpoint reports the failed execution
    res_execs = client.get("/api/scenarios/executions")
    assert res_execs.status_code == 200
    matches = [e for e in res_execs.get_json() if e["id"] == exec_id]
    assert len(matches) == 1
    assert matches[0]["status"] == "failed"


def test_scenario_execution_success_and_tracking(client):
    """
    Successful scenario execution commits all events atomically and logs
    a 'success' ScenarioExecution record with event count.
    """
    res = client.post("/api/scenarios/replay/run")
    assert res.status_code == 200
    data = res.get_json()
    assert data["scenario"] == "replay"
    assert data["event_count"] > 0
    assert "execution_id" in data
    exec_id = data["execution_id"]

    # Query executions endpoint
    res_execs = client.get("/api/scenarios/executions")
    assert res_execs.status_code == 200
    matches = [e for e in res_execs.get_json() if e["id"] == exec_id]
    assert len(matches) == 1
    assert matches[0]["status"] == "success"
    assert matches[0]["event_count"] == data["event_count"]
    assert matches[0]["completed_at"] is not None


def test_database_migration_005_lifecycle():
    """
    Migration 005 creates scenario_executions table and indexes cleanly,
    and downgrade_005 reverses it cleanly.
    """
    engine = create_engine("sqlite:///:memory:")
    mgr = MigrationManager(engine)
    mgr.apply_all()

    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "scenario_executions" in tables

    cols = {c["name"]: c for c in inspector.get_columns("scenario_executions")}
    assert "id" in cols
    assert "scenario_name" in cols
    assert "started_at" in cols
    assert "completed_at" in cols
    assert "status" in cols
    assert "event_count" in cols
    assert "error_message" in cols

    # Test rollback down to 004
    mgr.rollback_to("004_canonical_schema_fields")
    inspector = inspect(engine)
    assert "scenario_executions" not in inspector.get_table_names()

    # Re-apply 005
    mgr.apply_all()
    inspector = inspect(engine)
    assert "scenario_executions" in inspector.get_table_names()


def test_correlator_in_memory_transaction_rollback():
    """
    Verifies that TokenFamilyCorrelator.transaction() rolls back in-memory
    mutations to tokens, families, reuse_records, and _reuse_seen upon exception.
    """
    correlator = TokenFamilyCorrelator()

    # 1. Base state
    correlator.process_event({
        "event_id": "evt-base-1",
        "event_type": "token_issued",
        "time": "2026-08-07T16:00:00Z",
        "user_id": "u-mem",
        "token_hash": "f11111111111",
        "token_family": "fam-mem-1",
        "ip_hash": "123123123123",
        "device_id": "dev-mem-1",
        "result": "accepted"
    })

    assert "f11111111111" in correlator.tokens
    assert len(correlator.tokens) == 1

    # 2. Failed transaction
    try:
        with correlator.transaction():
            correlator.process_event({
                "event_id": "evt-base-2",
                "event_type": "token_refreshed",
                "time": "2026-08-07T16:10:00Z",
                "user_id": "u-mem",
                "token_hash": "f22222222222",
                "parent_token_hash": "f11111111111",
                "token_family": "fam-mem-1",
                "ip_hash": "123123123123",
                "device_id": "dev-mem-1",
                "result": "accepted"
            })
            assert "f22222222222" in correlator.tokens
            raise RuntimeError("Forced transaction failure")
    except RuntimeError:
        pass

    # Verify state rolled back to base state
    assert len(correlator.tokens) == 1
    assert "f22222222222" not in correlator.tokens
    assert correlator.tokens["f11111111111"].status == TokenStatus.ACTIVE
    assert correlator.tokens["f11111111111"].superseded_by is None
