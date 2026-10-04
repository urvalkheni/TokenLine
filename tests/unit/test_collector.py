import os
import sys
import pytest
import tempfile
import json
import logging
from unittest.mock import patch

# Add collector directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "backend", "collector"))

from app import app
from db import init_db, get_session, Event, session_scope

@pytest.fixture
def client():
    # Setup temporary database file
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    
    app.config["TESTING"] = True
    
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client

    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass

def get_db_events():
    db = get_session()
    events = db.query(Event).all()
    result = []
    for ev in events:
        result.append({
            "event_id": ev.event_id,
            "event_type": ev.event_type,
            "time": ev.time,
            "user_id": ev.user_id,
            "token_hash": ev.token_hash,
            "token_family": ev.token_family,
            "ip_hash": ev.ip_hash,
            "country": ev.country,
            "device_id": ev.device_id,
            "user_agent_family": ev.user_agent_family,
            "endpoint": ev.endpoint,
            "result": ev.result
        })
    db.close()
    return result

def test_ingest_valid_event(client):
    valid_event = {
        "event_id": "evt-12345",
        "event_type": "token_used",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-99",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "country": "US",
        "device_id": "device-macos-1",
        "user_agent_family": "Safari",
        "endpoint": "/api/v1/dashboard",
        "result": "accepted"
    }
    response = client.post("/events", json=valid_event)
    assert response.status_code == 201
    assert response.get_json()["status"] == "event persisted"

    # Verify database storage
    events = get_db_events()
    assert len(events) == 1
    assert events[0]["event_id"] == "evt-12345"
    assert events[0]["event_type"] == "token_used"

def test_ingest_malformed_schema_missing_fields(client):
    # Missing required field 'result'
    invalid_event = {
        "event_id": "evt-12346",
        "event_type": "token_used",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-99",
        "token_hash": "a4d3b8f1c29e",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-macos-1"
    }
    response = client.post("/events", json=invalid_event)
    assert response.status_code == 400
    res_data = response.get_json()
    assert "error" in res_data
    assert "Schema validation failed" in res_data["error"]

def test_ingest_malformed_schema_invalid_types(client):
    # 'time' is not formatted as date-time, country is too long (not 2 chars)
    invalid_event = {
        "event_id": "evt-12347",
        "event_type": "token_used",
        "time": "not-a-date-time",
        "user_id": "user-99",
        "token_hash": "a4d3b8f1c29e",
        "ip_hash": "f3b29c9e8d1a",
        "country": "USA",
        "device_id": "device-macos-1",
        "result": "accepted"
    }
    response = client.post("/events", json=invalid_event)
    assert response.status_code == 400

def test_ingest_raw_credentials_rejection_jwt(client):
    # token_hash contains a raw JWT pattern
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    invalid_event = {
        "event_id": "evt-12348",
        "event_type": "token_issued",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-99",
        "token_hash": raw_jwt,
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-macos-1",
        "result": "accepted"
    }
    response = client.post("/events", json=invalid_event)
    assert response.status_code == 400
    res_data = response.get_json()
    assert "Security validation failed" in res_data["error"]

def test_ingest_raw_credentials_rejection_bearer(client):
    # token_hash contains a Bearer token pattern
    invalid_event = {
        "event_id": "evt-12349",
        "event_type": "token_issued",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-99",
        "token_hash": "Bearer someTokenValue123",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-macos-1",
        "result": "accepted"
    }
    response = client.post("/events", json=invalid_event)
    assert response.status_code == 400

def test_non_json_payload(client):
    response = client.post("/events", data="not-json", headers={"Content-Type": "application/json"})
    assert response.status_code == 400

def test_ingest_duplicate_event_idempotency(client):
    valid_event = {
        "event_id": "evt-dup-1",
        "event_type": "token_issued",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-99",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-macos-1",
        "result": "accepted"
    }
    # First submission
    res1 = client.post("/events", json=valid_event)
    assert res1.status_code == 201
    assert res1.get_json()["status"] == "event persisted"

    # Second submission with same event_id
    res2 = client.post("/events", json=valid_event)
    assert res2.status_code == 200
    assert res2.get_json()["status"] == "event already exists"


def test_10mb_payload_rejected(client):
    """10 MB payloads are rejected with HTTP 413."""
    ten_mb_size = 10 * 1024 * 1024
    huge_data = "a" * ten_mb_size
    response = client.post(
        "/events",
        data=huge_data,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(ten_mb_size)
        }
    )
    assert response.status_code == 413
    res_data = response.get_json()
    assert "Payload too large" in res_data.get("error", "")


def test_maximum_field_lengths_rejected(client):
    """Fields exceeding maximum allowed lengths are rejected by JSON schema validation."""
    long_event = {
        "event_id": "e" * 129,
        "event_type": "token_issued",
        "time": "2026-08-16T10:00:00Z",
        "user_id": "user-test",
        "token_hash": "tok_hash_1",
        "token_family": "family-test",
        "ip_hash": "ip_hash_1",
        "country": "US",
        "device_id": "device-1",
        "result": "accepted"
    }
    response = client.post("/events", json=long_event)
    assert response.status_code == 400
    res_data = response.get_json()
    assert "Schema validation failed" in res_data.get("error", "")


def test_correlation_failure_is_logged_and_not_silent_success(client, caplog):
    """When correlation fails, it is visible in logs and does not silently report success."""
    valid_event = {
        "event_id": "evt-corr-fail-1",
        "event_type": "token_issued",
        "time": "2026-08-16T10:00:00Z",
        "user_id": "user-test",
        "token_hash": "tok_corr_fail",
        "token_family": "family-test",
        "ip_hash": "ip_hash_1",
        "country": "US",
        "device_id": "device-1",
        "result": "accepted"
    }

    with patch("app.process_event", side_effect=RuntimeError("Simulated correlator engine fault")):
        with caplog.at_level(logging.ERROR):
            response = client.post("/events", json=valid_event)

        assert response.status_code == 500
        res_data = response.get_json()
        assert "Correlation error" in res_data.get("error", "")
        assert any("Correlation failed for event evt-corr-fail-1" in record.message for record in caplog.records)


def test_safe_database_session_lifecycle():
    """Verify session_scope commits on success and safely rolls back and closes on exception."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    init_db()

    # Success case
    with session_scope() as session:
        session.add(Event(
            event_id="evt-scope-1",
            event_type="token_issued",
            time="2026-08-16T10:00:00Z",
            user_id="user-1",
            token_hash="tok-1",
            ip_hash="ip-1",
            device_id="dev-1",
            result="accepted"
        ))
        session.commit()

    with session_scope() as session:
        ev = session.query(Event).filter(Event.event_id == "evt-scope-1").first()
        assert ev is not None

    # Error case: rollback
    with pytest.raises(ValueError):
        with session_scope() as session:
            session.add(Event(
                event_id="evt-scope-2",
                event_type="token_issued",
                time="2026-08-16T10:00:00Z",
                user_id="user-1",
                token_hash="tok-2",
                ip_hash="ip-1",
                device_id="dev-1",
                result="accepted"
            ))
            raise ValueError("Forced error during session scope")

    with session_scope() as session:
        ev = session.query(Event).filter(Event.event_id == "evt-scope-2").first()
        assert ev is None

    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass

