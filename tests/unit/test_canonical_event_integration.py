import os
import sys
import tempfile
import pytest
import jsonschema
import json

from backend.collector.app import app
from backend.collector.db import init_db, get_session, Event
from backend.correlator import TokenFamilyCorrelator, process_event, TokenStatus
from simulator.runner import run_scenario, CANONICAL_SCENARIO_NAMES


@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    app.config["TESTING"] = True

    with app.test_client() as client:
        client.environ_base = {"HTTP_AUTHORIZATION": "Bearer tokenline-admin-secret"}
        with app.app_context():
            init_db()
        yield client

    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass


def test_collector_ingests_canonical_login_failed_without_token_hash(client):
    """
    Ensures login_failed events without a token_hash (since no token was issued)
    are accepted by schema validation and stored in DB with token_hash=None.
    """
    event = {
        "event_id": "evt-login-fail-001",
        "event_type": "login_failed",
        "time": "2026-10-26T14:00:00Z",
        "user_id": "demo-user",
        "ip_hash": "e3b0c44298fc1c14",
        "device_id": "dev-login-browser",
        "user_agent_family": "Firefox",
        "endpoint": "/auth/login",
        "result": "rejected",
        "schema_version": "1.0.0",
        "source": "demo_app",
        "is_simulation": False
    }

    res = client.post("/events", json=event)
    assert res.status_code == 201
    assert res.get_json()["status"] == "event persisted"

    db = get_session()
    saved = db.query(Event).filter(Event.event_id == "evt-login-fail-001").first()
    assert saved is not None
    assert saved.event_type == "login_failed"
    assert saved.token_hash is None
    assert saved.result == "rejected"
    assert saved.source == "demo_app"
    assert saved.schema_version == "1.0.0"
    assert saved.is_simulation is False
    db.close()


def test_collector_ingests_all_canonical_event_types(client):
    """Verifies that all 12 canonical event types are accepted by the collector."""
    canonical_types = [
        ("token_issued", "accepted", "a4d3b8f1c29e"),
        ("token_used", "accepted", "a4d3b8f1c29e"),
        ("token_refreshed", "accepted", "b5e4c9f2d30a"),
        ("token_revoked", "accepted", "c6f5d0a3e41b"),
        ("token_expired", "rejected", "d7a6e1b4f52c"),
        ("logout", "accepted", "e8b7f2c5a63d"),
        ("refresh_reuse_detected", "rejected", "f9c8a3d6b74e"),
        ("suspicious_location", "rejected", "0ad9b4e7c85f"),
        ("suspicious_device", "rejected", "1be0c5f8d960"),
        ("replay_detected", "rejected", "2cf1d6a9ea71"),
        ("login_failed", "rejected", None),
        ("token_rejected", "rejected", "3d02e7bae082"),
    ]

    for idx, (etype, result, thash) in enumerate(canonical_types):
        payload = {
            "event_id": f"evt-canonical-{idx}",
            "event_type": etype,
            "time": "2026-10-26T14:10:00Z",
            "user_id": f"user-{idx}",
            "ip_hash": "e3b0c44298fc1c14",
            "device_id": f"dev-{idx}",
            "result": result,
            "schema_version": "1.0.0",
            "source": "test_suite",
            "is_simulation": False
        }
        if thash is not None:
            payload["token_hash"] = thash
            payload["token_family"] = f"fam-{idx}"

        res = client.post("/events", json=payload)
        assert res.status_code == 201, f"Failed for {etype}: {res.get_json()}"


def test_collector_rejects_missing_required_fields(client):
    """Verifies rejection of events missing required schema fields."""
    base_valid = {
        "event_id": "evt-req-test",
        "event_type": "token_issued",
        "time": "2026-10-26T14:15:00Z",
        "user_id": "user-test",
        "ip_hash": "e3b0c44298fc1c14",
        "device_id": "dev-test",
        "result": "accepted"
    }

    for req_field in ["event_id", "event_type", "time", "user_id", "ip_hash", "device_id", "result"]:
        invalid_payload = dict(base_valid)
        del invalid_payload[req_field]
        res = client.post("/events", json=invalid_payload)
        assert res.status_code == 400
        assert "Schema validation failed" in res.get_json()["error"]


def test_correlator_handles_login_failed_without_false_replay():
    """
    Verifies that the Token-Family Correlator safely processes login_failed events
    without false positive replay alerts or family corruption.
    """
    correlator = TokenFamilyCorrelator()

    # Process login_failed with no token_hash
    result = correlator.process_event({
        "event_id": "evt-lf-1",
        "event_type": "login_failed",
        "time": "2026-10-26T14:20:00Z",
        "user_id": "demo-user",
        "ip_hash": "e3b0c44298fc1c14",
        "device_id": "dev-1",
        "result": "rejected"
    })
    assert result is None
    assert len(correlator.tokens) == 0
    assert len(correlator.reuse_records) == 0

    # Process normal token_issued
    correlator.process_event({
        "event_id": "evt-issue-1",
        "event_type": "token_issued",
        "time": "2026-10-26T14:21:00Z",
        "user_id": "demo-user",
        "token_hash": "token-hash-1111",
        "token_family": "fam-1",
        "ip_hash": "e3b0c44298fc1c14",
        "device_id": "dev-1",
        "result": "accepted"
    })
    assert len(correlator.tokens) == 1
    assert correlator.tokens["token-hash-1111"].status == TokenStatus.ACTIVE

    # Subsequent login_failed from another user/attacker does not affect fam-1
    result2 = correlator.process_event({
        "event_id": "evt-lf-2",
        "event_type": "login_failed",
        "time": "2026-10-26T14:22:00Z",
        "user_id": "demo-user",
        "ip_hash": "f4c1d55309fd2d25",
        "device_id": "dev-attacker",
        "result": "rejected"
    })
    assert result2 is None
    assert correlator.tokens["token-hash-1111"].status == TokenStatus.ACTIVE
    assert len(correlator.reuse_records) == 0


def test_simulator_events_conform_to_canonical_schema_and_mark_simulation():
    """Verifies that simulator scenarios produce canonical events with is_simulation=True."""
    for scenario_name in ["replay", "refresh-reuse", "normal"]:
        events = run_scenario(scenario_name, seed=42)
        assert len(events) > 0
        for evt in events:
            assert evt.get("is_simulation") is True
            assert evt.get("source") == "simulator"
            assert evt.get("schema_version") == "1.0.0"
            assert evt["result"] in ["accepted", "rejected"]


def test_collector_authentication_and_authorization(client):
    """Ensures collector enforces authentication on event ingestion."""
    event = {
        "event_id": "evt-auth-check",
        "event_type": "token_issued",
        "time": "2026-10-26T14:30:00Z",
        "user_id": "user-auth",
        "token_hash": "a4d3b8f1c29e",
        "ip_hash": "e3b0c44298fc1c14",
        "device_id": "dev-auth",
        "result": "accepted"
    }

    # 1. Missing credentials
    unauthed_client = app.test_client()
    res_no_auth = unauthed_client.post("/events", json=event)
    assert res_no_auth.status_code == 401

    # 2. Invalid credentials
    bad_auth_client = app.test_client()
    bad_auth_client.environ_base = {"HTTP_X_API_KEY": "completely-invalid-key"}
    res_bad_auth = bad_auth_client.post("/events", json=event)
    assert res_bad_auth.status_code == 401

    # 3. Read-only role trying to ingest -> 403 Forbidden
    read_client = app.test_client()
    read_client.environ_base = {"HTTP_X_API_KEY": "tokenline-read-secret"}
    res_forbidden = read_client.post("/events", json=event)
    assert res_forbidden.status_code == 403

    # 4. Ingest role -> 201 Created
    ingest_client = app.test_client()
    ingest_client.environ_base = {"HTTP_X_API_KEY": "tokenline-ingest-secret"}
    res_ingest = ingest_client.post("/events", json=event)
    assert res_ingest.status_code == 201
