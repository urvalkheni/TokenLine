"""
Comprehensive Regression Tests for Standardized Alert Model and Detection Evaluation.

Tests:
1. Alert model schema, required fields, and serialization.
2. Secret redaction on raw credentials/bearer tokens in evidence.
3. Database persistence and deduplication via unique constraint.
4. Separate incidents with the same rule/family are not incorrectly deduplicated.
5. Alert lifecycle transitions (open -> acknowledged -> resolved) and invalid transition rejection.
6. Evaluation metric calculations (precision, recall, specificity, F1, zero-denominator edge cases).
7. Reproducible dataset evaluation across all canonical rules and benign baselines.
8. Collector REST API endpoints (GET /api/alerts, GET /api/alerts/<id>, PATCH /api/alerts/<id>).
"""

import os
import pytest
import uuid
import json
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.collector.db import Base, Alert as DBAlert, Event as DBEvent, init_db
from backend.collector.app import create_app
from backend.correlator.models import (
    AlertRecord,
    AlertStatus,
    AlertSeverity,
    RULE_TOKEN_REUSE,
    RULE_REVOKED_USE,
    RULE_EXPIRED_USE,
    RULE_CONCURRENT_USE,
    RULE_IMPOSSIBLE_TRAVEL,
    RULE_TITLES,
    RULE_SEVERITIES,
    redact_secrets,
)
from backend.correlator.engine import TokenFamilyCorrelator
from backend.correlator.evaluator import (
    calculate_metrics,
    evaluate_incident,
    evaluate_dataset,
    EvaluationMetrics,
)
from simulator.evaluation_datasets import (
    LabeledIncident,
    get_evaluation_dataset,
)


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def correlator():
    return TokenFamilyCorrelator()


@pytest.fixture
def collector_client():
    import tempfile
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    old_db = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

    app = create_app({
        "TESTING": True,
        "TOKENLINE_ENV": "test",
    })
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client

    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass
    if old_db:
        os.environ["DATABASE_URL"] = old_db
    else:
        os.environ.pop("DATABASE_URL", None)


# =============================================================================
# 1. ALERT MODEL SCHEMA VALIDATION & SERIALIZATION
# =============================================================================

def test_alert_record_schema_and_serialization():
    now_iso = datetime.now(timezone.utc).isoformat()
    alert = AlertRecord(
        id="alert-test-1234",
        rule_id=RULE_TOKEN_REUSE,
        severity=AlertSeverity.CRITICAL.value,
        timestamp=now_iso,
        title=RULE_TITLES[RULE_TOKEN_REUSE],
        explanation="Test explanation",
        event_refs=["evt-001"],
        token_family_id="family-123",
        token_hash="hash-abc",
        user_id="user-1",
        evidence={"detail": "sample evidence"},
    )

    # Check required fields
    assert alert.id == "alert-test-1234"
    assert alert.rule_id == RULE_TOKEN_REUSE
    assert alert.severity == "critical"
    assert alert.status == "open"
    assert alert.event_refs == ["evt-001"]
    assert alert.token_family_id == "family-123"
    assert alert.token_hash == "hash-abc"
    assert alert.user_id == "user-1"
    assert alert.dedup_fingerprint == f"{RULE_TOKEN_REUSE}:hash-abc:evt-001"
    assert alert.created_at == now_iso
    assert alert.updated_at == now_iso

    # Test serialization
    data = alert.to_dict()
    assert isinstance(data, dict)
    assert data["id"] == "alert-test-1234"
    assert data["rule_id"] == RULE_TOKEN_REUSE
    assert data["dedup_fingerprint"] == f"{RULE_TOKEN_REUSE}:hash-abc:evt-001"
    assert data["event_refs"] == ["evt-001"]
    # Check compatibility properties for legacy consumers
    assert data["detection_type"] == "refresh_reuse"
    assert data["detected_at"] == now_iso
    assert data["reused_at"] == now_iso
    assert data["attempted_event_id"] == "evt-001"
    assert data["token_family"] == "family-123"


# =============================================================================
# 2. SECRET REDACTION TESTS
# =============================================================================

def test_secret_redaction_in_alerts():
    leaked_evidence = {
        "password": "super-secret-password-123",
        "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy.sig",
        "nested": {
            "api_secret": "sk_live_abcdef1234567890",
            "safe_hash": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        },
        "raw_token": "secret_token_data",
        "public_meta": "benign-value",
    }

    cleaned = redact_secrets(leaked_evidence)
    assert cleaned["password"] == "[REDACTED_SECRET]"
    assert cleaned["authorization"] == "[REDACTED_SECRET]"
    assert cleaned["nested"]["api_secret"] == "[REDACTED_SECRET]"
    assert cleaned["nested"]["safe_hash"] == "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
    assert cleaned["raw_token"] == "[REDACTED_SECRET]"
    assert cleaned["public_meta"] == "benign-value"

    # Verify AlertRecord automatically applies redaction
    alert = AlertRecord(
        id="alert-redact-1",
        rule_id=RULE_TOKEN_REUSE,
        severity="critical",
        timestamp=datetime.now(timezone.utc).isoformat(),
        title="Reuse",
        explanation="Test",
        event_refs=["evt-1"],
        evidence=leaked_evidence,
    )
    assert alert.evidence["password"] == "[REDACTED_SECRET]"
    assert alert.evidence["authorization"] == "[REDACTED_SECRET]"


# =============================================================================
# 3. DATABASE PERSISTENCE & UNIQUE CONSTRAINT DEDUPLICATION
# =============================================================================

def test_alert_db_persistence_and_deduplication(in_memory_db):
    correlator = TokenFamilyCorrelator()
    base_time = datetime(2026, 10, 27, 9, 0, 0, tzinfo=timezone.utc)
    t_a = "token-hash-a"
    t_b = "token-hash-b"
    t_c = "token-hash-c"
    fam = "family-dedup-test"

    # Step 1: Issue Token A and rotate to Token B
    e1 = {
        "event_id": "evt-rot-1",
        "event_type": "token_issued",
        "time": base_time.isoformat(),
        "token_hash": t_a,
        "token_family": fam,
    }
    e2 = {
        "event_id": "evt-rot-2",
        "event_type": "token_refreshed",
        "time": (base_time + timedelta(seconds=10)).isoformat(),
        "token_hash": t_b,
        "parent_token_hash": t_a,
        "token_family": fam,
    }
    correlator.process_event(e1, db_session=in_memory_db)
    correlator.process_event(e2, db_session=in_memory_db)

    # Step 2: Trigger refresh-token reuse on Token A
    reuse_event = {
        "event_id": "evt-reuse-attack",
        "event_type": "token_refreshed",
        "time": (base_time + timedelta(seconds=20)).isoformat(),
        "token_hash": t_c,
        "parent_token_hash": t_a,
        "token_family": fam,
    }
    res1 = correlator.process_event(reuse_event, db_session=in_memory_db)
    assert res1 is not None

    # Verify exactly 1 alert exists in DB
    alerts_in_db = in_memory_db.query(DBAlert).all()
    assert len(alerts_in_db) == 1
    first_alert = alerts_in_db[0]
    assert first_alert.rule_id == RULE_TOKEN_REUSE
    assert first_alert.token_hash == t_a
    assert first_alert.dedup_fingerprint == f"{RULE_TOKEN_REUSE}:{t_a}:evt-reuse-attack"

    # Step 3: Replay identical reuse event 10 times -> dedup MUST prevent duplicates
    for _ in range(10):
        correlator.process_event(reuse_event, db_session=in_memory_db)

    # Verify STILL exactly 1 alert in DB and 1 in-memory alert
    assert in_memory_db.query(DBAlert).count() == 1
    assert len(correlator.get_alerts()) == 1


def test_separate_incidents_not_incorrectly_deduplicated(in_memory_db):
    correlator = TokenFamilyCorrelator()
    base_time = datetime(2026, 10, 27, 9, 0, 0, tzinfo=timezone.utc)
    t_a = "token-hash-incident-a"
    t_b = "token-hash-incident-b"
    fam = "family-multi-incident"

    # Rotate Token A -> Token B
    correlator.process_event({
        "event_id": "evt-init",
        "event_type": "token_issued",
        "time": base_time.isoformat(),
        "token_hash": t_a,
        "token_family": fam,
    }, db_session=in_memory_db)
    correlator.process_event({
        "event_id": "evt-rot",
        "event_type": "token_refreshed",
        "time": (base_time + timedelta(seconds=10)).isoformat(),
        "token_hash": t_b,
        "parent_token_hash": t_a,
        "token_family": fam,
    }, db_session=in_memory_db)

    # Incident 1: First reuse attempt from event 1
    correlator.process_event({
        "event_id": "evt-reuse-1",
        "event_type": "token_refreshed",
        "time": (base_time + timedelta(seconds=20)).isoformat(),
        "token_hash": "child-attempt-1",
        "parent_token_hash": t_a,
        "token_family": fam,
    }, db_session=in_memory_db)

    # Incident 2: Second reuse attempt from event 2
    correlator.process_event({
        "event_id": "evt-reuse-2",
        "event_type": "token_refreshed",
        "time": (base_time + timedelta(seconds=30)).isoformat(),
        "token_hash": "child-attempt-2",
        "parent_token_hash": t_a,
        "token_family": fam,
    }, db_session=in_memory_db)

    # Both incidents MUST be recorded because their event_id / fingerprints differ!
    db_alerts = in_memory_db.query(DBAlert).all()
    assert len(db_alerts) == 2
    fingerprints = {a.dedup_fingerprint for a in db_alerts}
    assert f"{RULE_TOKEN_REUSE}:{t_a}:evt-reuse-1" in fingerprints
    assert f"{RULE_TOKEN_REUSE}:{t_a}:evt-reuse-2" in fingerprints


# =============================================================================
# 4. ALERT LIFECYCLE TRANSITIONS & VALIDATION
# =============================================================================

def test_alert_lifecycle_state_transitions(in_memory_db):
    correlator = TokenFamilyCorrelator()
    alert = correlator._record_alert(
        rule_id=RULE_TOKEN_REUSE,
        token_family_id="fam-1",
        event_refs=["evt-1"],
        timestamp=datetime.now(timezone.utc).isoformat(),
        token_hash="hash-1",
    )
    # Save to DB
    db_alert = DBAlert(
        id=alert.id,
        rule_id=alert.rule_id,
        severity=alert.severity,
        status=alert.status,
        timestamp=alert.timestamp,
        title=alert.title,
        explanation=alert.explanation,
        event_refs_json=json.dumps(alert.event_refs),
        token_family_id=alert.token_family_id,
        token_hash=alert.token_hash,
        user_id=alert.user_id,
        evidence_json=json.dumps(alert.evidence),
        dedup_fingerprint=alert.dedup_fingerprint,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )
    in_memory_db.add(db_alert)
    in_memory_db.commit()

    assert alert.status == AlertStatus.OPEN.value

    # 1. Transition open -> acknowledged
    updated_1 = correlator.update_alert_status(alert.id, AlertStatus.ACKNOWLEDGED.value, db_session=in_memory_db)
    assert updated_1.status == AlertStatus.ACKNOWLEDGED.value
    assert in_memory_db.query(DBAlert).filter(DBAlert.id == alert.id).first().status == "acknowledged"

    # 2. Transition acknowledged -> resolved
    updated_2 = correlator.update_alert_status(alert.id, AlertStatus.RESOLVED.value, db_session=in_memory_db)
    assert updated_2.status == AlertStatus.RESOLVED.value
    assert in_memory_db.query(DBAlert).filter(DBAlert.id == alert.id).first().status == "resolved"

    # 3. Invalid transition from resolved -> open MUST be rejected
    with pytest.raises(ValueError, match="Cannot transition alert from terminal status"):
        correlator.update_alert_status(alert.id, AlertStatus.OPEN.value, db_session=in_memory_db)

    # 4. Completely invalid status string MUST be rejected
    with pytest.raises(ValueError, match="Invalid alert status"):
        correlator.update_alert_status(alert.id, "bogus_status", db_session=in_memory_db)


# =============================================================================
# 5. METRIC CALCULATION TESTS (INCLUDING ZERO-DENOMINATOR EDGE CASES)
# =============================================================================

def test_metric_calculations_and_zero_denominator_handling():
    # Perfect performance: 10 TP, 0 FP, 10 TN, 0 FN
    m_perfect = calculate_metrics(tp=10, fp=0, tn=10, fn=0)
    assert m_perfect.precision == 1.0
    assert m_perfect.recall == 1.0
    assert m_perfect.specificity == 1.0
    assert m_perfect.f1_score == 1.0
    d_perfect = m_perfect.to_dict()
    assert d_perfect["precision_display"] == "100.0%"
    assert d_perfect["recall_display"] == "100.0%"
    assert d_perfect["f1_display"] == "100.0%"

    # Zero-denominator: No attacks present (tp=0, fn=0) -> recall denominator is 0
    m_zero_recall = calculate_metrics(tp=0, fp=0, tn=10, fn=0)
    assert m_zero_recall.recall is None
    assert m_zero_recall.to_dict()["recall_display"] == "N/A"
    assert m_zero_recall.f1_score is None
    assert m_zero_recall.to_dict()["f1_display"] == "N/A"

    # Zero-denominator: No alerts triggered (tp=0, fp=0) -> precision denominator is 0
    m_zero_prec = calculate_metrics(tp=0, fp=0, tn=10, fn=5)
    assert m_zero_prec.precision is None
    assert m_zero_prec.to_dict()["precision_display"] == "N/A"
    assert m_zero_prec.f1_score is None

    # Zero-denominator: No negatives present (tn=0, fp=0) -> specificity denominator is 0
    m_zero_spec = calculate_metrics(tp=5, fp=0, tn=0, fn=0)
    assert m_zero_spec.specificity is None
    assert m_zero_spec.to_dict()["specificity_display"] == "N/A"

    # Specific mixed values
    m_mixed = calculate_metrics(tp=8, fp=2, tn=9, fn=1)
    assert m_mixed.precision == 0.8  # 8 / 10
    assert m_mixed.recall == 8 / 9   # 8 / 9
    assert m_mixed.specificity == 9 / 11  # 9 / 11
    expected_f1 = 2 * (0.8 * (8 / 9)) / (0.8 + (8 / 9))
    assert abs(m_mixed.f1_score - expected_f1) < 1e-6


# =============================================================================
# 6. REPRODUCIBLE DATASET EVALUATION ACROSS ALL RULES
# =============================================================================

def test_reproducible_dataset_evaluation():
    dataset = get_evaluation_dataset()
    assert len(dataset) == 11

    report = evaluate_dataset(dataset)
    assert report.total_incidents == 11
    assert report.normal_incidents == 6
    assert report.attack_incidents == 5

    # Aggregate performance across all incidents
    agg = report.aggregate_metrics
    assert agg.tp == 5
    assert agg.fp == 0
    assert agg.tn == 6
    assert agg.fn == 0
    assert agg.precision == 1.0
    assert agg.recall == 1.0
    assert agg.specificity == 1.0
    assert agg.f1_score == 1.0

    # Per-rule breakdown verification
    for rule_id in [RULE_TOKEN_REUSE, RULE_REVOKED_USE, RULE_EXPIRED_USE, RULE_CONCURRENT_USE, RULE_IMPOSSIBLE_TRAVEL]:
        r_m = report.rule_metrics[rule_id]
        assert r_m.tp == 1, f"Rule {rule_id} should have exactly 1 TP"
        assert r_m.fp == 0, f"Rule {rule_id} should have 0 FP"
        assert r_m.fn == 0, f"Rule {rule_id} should have 0 FN"
        assert r_m.tn == 10, f"Rule {rule_id} should have 10 TN"
        assert r_m.precision == 1.0
        assert r_m.recall == 1.0
        assert r_m.f1_score == 1.0

    # Markdown report generation
    md = report.generate_markdown_report()
    assert "# TokenLine Detection Engine Evaluation Report" in md
    assert "RULE-TOKEN-REUSE" in md
    assert "RULE-IMPOSSIBLE-TRAVEL" in md
    assert "100.0%" in md


# =============================================================================
# 7. COLLECTOR REST API ENDPOINT TESTS
# =============================================================================

def test_collector_alerts_api_endpoints(collector_client):
    headers_admin = {"X-API-Key": "tokenline-admin-secret"}
    headers_read = {"X-API-Key": "tokenline-read-secret"}

    # 1. Ingest normal rotation and reuse attack to generate an alert
    base_time = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    fam = "family-api-test"
    import hashlib
    t_a = hashlib.sha256(b"token-api-a").hexdigest()
    t_b = hashlib.sha256(b"token-api-b").hexdigest()
    t_c = hashlib.sha256(b"token-api-c").hexdigest()

    # Issue A
    res = collector_client.post("/api/events", json={
        "event_id": "api-evt-1",
        "event_type": "token_issued",
        "time": base_time.isoformat(),
        "token_hash": t_a,
        "token_family": fam,
        "user_id": "api-user",
        "endpoint": "/api/v1/auth/login",
        "device_id": "dev-1",
        "ip_hash": "1111222233334444555566667777888811112222333344445555666677778888",
        "country": "IN",
        "user_agent_family": "Chrome",
        "result": "accepted",
        "schema_version": "1.0.0",
        "source": "demo-app",
    }, headers=headers_admin)
    assert res.status_code == 201

    # Refresh A -> B
    res = collector_client.post("/api/events", json={
        "event_id": "api-evt-2",
        "event_type": "token_refreshed",
        "time": (base_time + timedelta(seconds=10)).isoformat(),
        "token_hash": t_b,
        "parent_token_hash": t_a,
        "token_family": fam,
        "user_id": "api-user",
        "endpoint": "/api/v1/auth/refresh",
        "device_id": "dev-1",
        "ip_hash": "1111222233334444555566667777888811112222333344445555666677778888",
        "country": "IN",
        "user_agent_family": "Chrome",
        "result": "accepted",
        "schema_version": "1.0.0",
        "source": "demo-app",
    }, headers=headers_admin)
    assert res.status_code == 201

    # Reuse rotated Token A -> should trigger RULE-TOKEN-REUSE alert
    res = collector_client.post("/api/events", json={
        "event_id": "api-evt-3-attack",
        "event_type": "token_refreshed",
        "time": (base_time + timedelta(seconds=20)).isoformat(),
        "token_hash": t_c,
        "parent_token_hash": t_a,
        "token_family": fam,
        "user_id": "api-user",
        "endpoint": "/api/v1/auth/refresh",
        "device_id": "attacker-box",
        "ip_hash": "1111222233334444555566667777888811112222333344445555666677778888",
        "country": "IN",
        "user_agent_family": "Chrome",
        "result": "rejected",
        "schema_version": "1.0.0",
        "source": "demo-app",
    }, headers=headers_admin)
    assert res.status_code == 201

    # 2. GET /api/alerts
    res = collector_client.get("/api/alerts", headers=headers_read)
    assert res.status_code == 200
    alerts = res.get_json()
    assert isinstance(alerts, list)
    assert len(alerts) >= 1

    alert = next(a for a in alerts if a["token_family_id"] == fam)
    assert alert["rule_id"] == RULE_TOKEN_REUSE
    assert alert["status"] == "open"
    alert_id = alert["id"]

    # 3. GET /api/alerts/<id>
    res = collector_client.get(f"/api/alerts/{alert_id}", headers=headers_read)
    assert res.status_code == 200
    single = res.get_json()
    assert single["id"] == alert_id
    assert single["rule_id"] == RULE_TOKEN_REUSE

    # 4. PATCH /api/alerts/<id> - Acknowledge alert
    res = collector_client.patch(f"/api/alerts/{alert_id}", json={"status": "acknowledged"}, headers=headers_admin)
    assert res.status_code == 200
    patched = res.get_json()
    assert patched["status"] == "acknowledged"

    # 5. PATCH /api/alerts/<id> - Resolve alert
    res = collector_client.patch(f"/api/alerts/{alert_id}", json={"status": "resolved"}, headers=headers_admin)
    assert res.status_code == 200
    patched2 = res.get_json()
    assert patched2["status"] == "resolved"

    # 6. PATCH /api/alerts/<id> - Reopening resolved alert rejected
    res = collector_client.patch(f"/api/alerts/{alert_id}", json={"status": "open"}, headers=headers_admin)
    assert res.status_code == 400
    assert "Invalid state transition" in res.get_json()["error"]
