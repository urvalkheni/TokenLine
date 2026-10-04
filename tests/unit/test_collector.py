import os
import sys
import pytest
import tempfile
import json

from backend.collector.app import app
from backend.collector.db import init_db, get_session, Event


@pytest.fixture
def client():
    # Setup temporary database file
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
    # Payloads of 10 MB or larger must be rejected with 413
    ten_mb_payload = "x" * (10 * 1024 * 1024)
    response = client.post(
        "/events",
        data=ten_mb_payload,
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
    res_data = response.get_json()
    assert "Payload too large" in res_data.get("error", "")


def test_maximum_field_lengths_rejected(client):
    # user_id > 128 characters should fail schema validation
    oversized_user_event = {
        "event_id": "evt-oversized-1",
        "event_type": "token_used",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "u" * 129,
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "country": "US",
        "device_id": "device-1",
        "result": "accepted"
    }
    response = client.post("/events", json=oversized_user_event)
    assert response.status_code == 400
    assert "Schema validation failed" in response.get_json().get("error", "")

    # token_hash > 256 characters should fail schema validation
    oversized_token_event = {
        "event_id": "evt-oversized-2",
        "event_type": "token_used",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "valid-user",
        "token_hash": "h" * 257,
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "country": "US",
        "device_id": "device-1",
        "result": "accepted"
    }
    response = client.post("/events", json=oversized_token_event)
    assert response.status_code == 400
    assert "Schema validation failed" in response.get_json().get("error", "")


def test_correlation_failure_is_logged_and_not_silent_success(client, monkeypatch, caplog):
    import logging
    import sys

    def failing_process_event(data, db_sess):
        raise RuntimeError("Simulated engine failure during correlation")

    collector_mod = sys.modules["backend.collector.app"]
    monkeypatch.setattr(collector_mod, "process_event", failing_process_event)

    valid_event = {
        "event_id": "evt-correlate-fail",
        "event_type": "token_issued",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-fail",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-fail",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-fail",
        "result": "accepted"
    }

    with caplog.at_level(logging.ERROR, logger="tokenline.collector"):
        response = client.post("/events", json=valid_event)

    assert response.status_code == 500
    res_data = response.get_json()
    assert res_data.get("error") == "Correlation error"
    assert "Correlation failed" in res_data.get("message", "")
    assert "Correlation failed for event evt-correlate-fail" in caplog.text
    assert "Simulated engine failure during correlation" in caplog.text


def test_safe_database_session_lifecycle():
    from backend.collector.db import session_scope, Event

    # Normal scope execution commits and closes cleanly
    with session_scope() as session:
        count = session.query(Event).count()
        assert isinstance(count, int)
        assert session.is_active

    # Failing block rolls back and closes cleanly
    with pytest.raises(ValueError, match="Boom"):
        with session_scope() as session:
            dummy_ev = Event(
                event_id="evt-rollback-test",
                event_type="token_issued",
                time="2026-08-07T12:20:00Z",
                user_id="user-rb",
                token_hash="tok-rb",
                ip_hash="ip-rb",
                device_id="dev-rb",
                result="accepted"
            )
            session.add(dummy_ev)
            raise ValueError("Boom")

    # Verify dummy_ev was rolled back
    with session_scope() as session:
        ev = session.query(Event).filter(Event.event_id == "evt-rollback-test").first()
        assert ev is None


def test_collector_routes_authentication_required(client):
    valid_event = {
        "event_id": "evt-auth-test-1",
        "event_type": "token_used",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-auth",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "country": "US",
        "device_id": "device-1",
        "result": "accepted"
    }

    # 1. Unauthenticated requests (empty/missing Authorization header) must return 401
    unauth_headers = {"Authorization": ""}

    res_post_events = client.post("/events", json=valid_event, headers=unauth_headers)
    assert res_post_events.status_code == 401
    assert res_post_events.get_json()["error"] == "Unauthorized"

    res_post_api_events = client.post("/api/events", json=valid_event, headers=unauth_headers)
    assert res_post_api_events.status_code == 401
    assert res_post_api_events.get_json()["error"] == "Unauthorized"

    res_get_events = client.get("/events", headers=unauth_headers)
    assert res_get_events.status_code == 401
    assert res_get_events.get_json()["error"] == "Unauthorized"

    res_get_api_events = client.get("/api/events", headers=unauth_headers)
    assert res_get_api_events.status_code == 401
    assert res_get_api_events.get_json()["error"] == "Unauthorized"

    # 2. Invalid authentication credentials must return 401
    invalid_headers = {"Authorization": "Bearer invalid-garbage-token"}
    res_invalid = client.post("/events", json=valid_event, headers=invalid_headers)
    assert res_invalid.status_code == 401
    assert res_invalid.get_json()["error"] == "Unauthorized"


def test_collector_routes_authorization_boundaries(client):
    valid_event_1 = {
        "event_id": "evt-auth-priv-1",
        "event_type": "token_issued",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-auth",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "country": "US",
        "device_id": "device-1",
        "result": "accepted"
    }

    # 1. User with read role cannot ingest events (must return 403 Forbidden)
    read_headers = {"Authorization": "Bearer tokenline-read-secret"}
    res_read_post = client.post("/events", json=valid_event_1, headers=read_headers)
    assert res_read_post.status_code == 403
    assert res_read_post.get_json()["error"] == "Forbidden"

    res_read_post_api = client.post("/api/events", json=valid_event_1, headers=read_headers)
    assert res_read_post_api.status_code == 403
    assert res_read_post_api.get_json()["error"] == "Forbidden"

    # Read role CAN perform read operations
    res_read_get = client.get("/events", headers=read_headers)
    assert res_read_get.status_code == 200

    # 2. Client with ingest role CAN ingest events
    ingest_headers = {"Authorization": "Bearer tokenline-ingest-secret"}
    res_ingest_post = client.post("/events", json=valid_event_1, headers=ingest_headers)
    assert res_ingest_post.status_code == 201

    # 3. Client with admin role CAN ingest events
    valid_event_2 = dict(valid_event_1, event_id="evt-auth-priv-2", token_hash="b5e4c9f2d30f")
    admin_headers = {"Authorization": "Bearer tokenline-admin-secret"}
    res_admin_post = client.post("/api/events", json=valid_event_2, headers=admin_headers)
    assert res_admin_post.status_code == 201


def test_api_key_header_support(client):
    valid_event = {
        "event_id": "evt-api-key-test",
        "event_type": "token_used",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-auth",
        "token_hash": "c6f5d0a3e41a",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "country": "US",
        "device_id": "device-1",
        "result": "accepted"
    }

    # X-API-Key with admin credentials
    res_admin = client.post(
        "/events",
        json=valid_event,
        headers={"Authorization": "", "X-API-Key": "tokenline-admin-secret"}
    )
    assert res_admin.status_code == 201

    # X-API-Key with read-only credentials attempting ingest
    valid_event_2 = dict(valid_event, event_id="evt-api-key-test-2")
    res_read = client.post(
        "/events",
        json=valid_event_2,
        headers={"Authorization": "", "X-API-Key": "tokenline-read-secret"}
    )
    assert res_read.status_code == 403


def test_invalid_time_format_rejected(client):
    event = {
        "event_id": "evt-invalid-time",
        "event_type": "token_used",
        "time": "not-a-date",
        "user_id": "user-test",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "country": "US",
        "device_id": "device-1",
        "result": "accepted"
    }
    response = client.post("/events", json=event)
    assert response.status_code == 400
    res_data = response.get_json()
    assert res_data["error"] == "Schema validation failed"


def test_invalid_hash_fields_rejected(client):
    base_event = {
        "event_id": "evt-hash-test",
        "event_type": "token_used",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-test",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "country": "US",
        "device_id": "device-1",
        "result": "accepted"
    }

    # 1. Invalid token_hash (non-hex, special characters)
    evt_bad_token_hash = dict(base_event, token_hash="invalid_token_hash_not_hex!")
    res = client.post("/events", json=evt_bad_token_hash)
    assert res.status_code == 400
    assert "Schema validation failed" in res.get_json()["error"]

    # 2. Invalid parent_token_hash (non-hex, malformed)
    evt_bad_parent = dict(base_event, event_type="token_refreshed", parent_token_hash="bad-parent-hash-xyz")
    res = client.post("/events", json=evt_bad_parent)
    assert res.status_code == 400
    assert "Schema validation failed" in res.get_json()["error"]

    # 3. Invalid ip_hash (raw IP address instead of hash representation)
    evt_bad_ip_hash = dict(base_event, ip_hash="192.168.1.100")
    res = client.post("/events", json=evt_bad_ip_hash)
    assert res.status_code == 400
    assert "Schema validation failed" in res.get_json()["error"]


def test_raw_token_like_values_rejected_in_hash_fields(client):
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    raw_bearer = "Bearer someTokenValue123"

    base_event = {
        "event_id": "evt-raw-token-test",
        "event_type": "token_issued",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-test",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-1",
        "result": "accepted"
    }

    # Raw token in token_hash
    evt_raw_th = dict(base_event, token_hash=raw_jwt)
    res_th = client.post("/events", json=evt_raw_th)
    assert res_th.status_code == 400

    evt_bearer_th = dict(base_event, token_hash=raw_bearer)
    res_bearer_th = client.post("/events", json=evt_bearer_th)
    assert res_bearer_th.status_code == 400

    # Raw token in parent_token_hash
    evt_raw_pth = dict(base_event, event_type="token_refreshed", parent_token_hash=raw_jwt)
    res_pth = client.post("/events", json=evt_raw_pth)
    assert res_pth.status_code == 400

    evt_bearer_pth = dict(base_event, event_type="token_refreshed", parent_token_hash=raw_bearer)
    res_bearer_pth = client.post("/events", json=evt_bearer_pth)
    assert res_bearer_pth.status_code == 400


def test_new_event_types_login_failed_and_token_rejected(client):
    # Valid login_failed event
    login_failed_event = {
        "event_id": "evt-login-failed-1",
        "event_type": "login_failed",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-test",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-1",
        "result": "rejected"
    }
    res_lf = client.post("/events", json=login_failed_event)
    assert res_lf.status_code == 201
    assert res_lf.get_json()["status"] == "event persisted"

    # Valid token_rejected event
    token_rejected_event = {
        "event_id": "evt-token-rejected-1",
        "event_type": "token_rejected",
        "time": "2026-08-07T12:22:00Z",
        "user_id": "user-test",
        "token_hash": "c6f5d0a3e41a",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-1",
        "result": "rejected"
    }
    res_tr = client.post("/events", json=token_rejected_event)
    assert res_tr.status_code == 201
    assert res_tr.get_json()["status"] == "event persisted"


def test_existing_valid_event_types_still_accepted(client):
    existing_types = [
        ("token_issued", "accepted"),
        ("token_used", "accepted"),
        ("token_refreshed", "accepted"),
        ("token_revoked", "rejected"),
        ("token_expired", "rejected"),
        ("logout", "accepted"),
        ("refresh_reuse_detected", "rejected"),
        ("suspicious_location", "rejected"),
        ("suspicious_device", "rejected"),
        ("replay_detected", "rejected")
    ]

    for idx, (etype, res_status) in enumerate(existing_types):
        evt = {
            "event_id": f"evt-existing-type-{idx}",
            "event_type": etype,
            "time": "2026-08-07T12:20:00Z",
            "user_id": "user-test",
            "token_hash": f"a4d3b8f1c2{idx:02d}",
            "token_family": "family-xyz",
            "ip_hash": "f3b29c9e8d1a",
            "device_id": "device-1",
            "result": res_status
        }
        res = client.post("/events", json=evt)
        assert res.status_code == 201, f"Expected 201 for {etype}, got {res.status_code}: {res.get_data(as_text=True)}"


# ==============================================================================
# ISSUE #9: SECURITY REGRESSION TESTS - RAW CREDENTIAL PROTECTION
# ==============================================================================

RAW_TEST_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_issue9_known_jwt_credential_representation_rejected(client):
    """Test 1: Known JWT/credential representation is rejected."""
    bad_event = {
        "event_id": "evt-issue9-jwt-1",
        "event_type": "token_issued",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-test",
        "token_hash": RAW_TEST_JWT,
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-1",
        "result": "accepted"
    }
    res = client.post("/events", json=bad_event)
    assert res.status_code == 400
    assert "Security validation failed" in res.get_json()["error"]


def test_issue9_credential_different_prefix_or_location_rejected(client):
    """Test 2: Same credential with a different prefix/location is rejected."""
    prefixes = [
        f"Bearer {RAW_TEST_JWT}",
        f"Basic {RAW_TEST_JWT}",
        f"Token {RAW_TEST_JWT}",
        f"JWT {RAW_TEST_JWT}",
        f"token={RAW_TEST_JWT}",
        f"access_token={RAW_TEST_JWT}",
        f"id_token:{RAW_TEST_JWT}",
    ]
    for idx, prefixed in enumerate(prefixes):
        evt = {
            "event_id": f"evt-issue9-prefix-{idx}",
            "event_type": "token_used",
            "time": "2026-08-07T12:20:00Z",
            "user_id": "user-test",
            "token_hash": "a4d3b8f1c29e",
            "token_family": "family-xyz",
            "ip_hash": "f3b29c9e8d1a",
            "endpoint": f"/api/v1/resource?{prefixed}",
            "device_id": "device-1",
            "result": "accepted"
        }
        res = client.post("/events", json=evt)
        assert res.status_code == 400
        assert "Security validation failed" in res.get_json()["error"]


def test_issue9_raw_jwt_in_token_hash_rejected(client):
    """Test 3: Raw JWT placed in token_hash is rejected."""
    evt = {
        "event_id": "evt-issue9-th-jwt",
        "event_type": "token_issued",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-test",
        "token_hash": RAW_TEST_JWT,
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-1",
        "result": "accepted"
    }
    res = client.post("/events", json=evt)
    assert res.status_code == 400
    assert "Security validation failed" in res.get_json()["error"]


def test_issue9_raw_jwt_in_parent_token_hash_rejected(client):
    """Test 4: Raw JWT placed in parent_token_hash is rejected."""
    evt = {
        "event_id": "evt-issue9-pth-jwt",
        "event_type": "token_refreshed",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-test",
        "token_hash": "a4d3b8f1c29e",
        "parent_token_hash": RAW_TEST_JWT,
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-1",
        "result": "accepted"
    }
    res = client.post("/events", json=evt)
    assert res.status_code == 400
    assert "Security validation failed" in res.get_json()["error"]


def test_issue9_raw_jwt_in_alternate_fields_rejected(client):
    """Test 5: Raw JWT placed in other allowed event fields is rejected."""
    alternate_fields = [
        ("endpoint", f"/api/v1/auth?token={RAW_TEST_JWT}"),
        ("device_id", f"device-{RAW_TEST_JWT[:40]}"),
        ("user_agent_family", f"Mozilla/5.0 {RAW_TEST_JWT}"),
        ("user_id", f"user-{RAW_TEST_JWT[:40]}"),
        ("token_family", f"family-{RAW_TEST_JWT[:40]}"),
    ]
    for field_name, bad_value in alternate_fields:
        evt = {
            "event_id": f"evt-issue9-alt-{field_name}",
            "event_type": "token_issued",
            "time": "2026-08-07T12:20:00Z",
            "user_id": "user-test",
            "token_hash": "a4d3b8f1c29e",
            "token_family": "family-xyz",
            "ip_hash": "f3b29c9e8d1a",
            "device_id": "device-1",
            "result": "accepted"
        }
        evt[field_name] = bad_value
        res = client.post("/events", json=evt)
        assert res.status_code == 400, f"Expected 400 when raw JWT placed in {field_name}, got {res.status_code}"
        assert "Security validation failed" in res.get_json()["error"]


def test_issue9_jwt_split_or_positioned_to_bypass_old_regex_rejected(client):
    """Test 6: JWT split or positioned so the old regex would miss it is rejected."""
    import urllib.parse

    bypasses = [
        # 1. URL percent-encoded JWT
        urllib.parse.quote(RAW_TEST_JWT),
        # 2. Embedded inside complex query string
        f"/oauth/callback?state=xyz123&id_token={RAW_TEST_JWT}&scope=openid",
        # 3. Custom scheme header
        f"JWT {RAW_TEST_JWT}",
        # 4. Whitespace and newline padding inside the string
        f"  \t\n{RAW_TEST_JWT}\n  ",
        # 5. Token assignment inside endpoint path
        f"/auth/token={RAW_TEST_JWT}",
    ]
    for idx, bypass_val in enumerate(bypasses):
        evt = {
            "event_id": f"evt-issue9-split-{idx}",
            "event_type": "token_used",
            "time": "2026-08-07T12:20:00Z",
            "user_id": "user-test",
            "token_hash": "a4d3b8f1c29e",
            "token_family": "family-xyz",
            "ip_hash": "f3b29c9e8d1a",
            "endpoint": bypass_val,
            "device_id": "device-1",
            "result": "accepted"
        }
        res = client.post("/events", json=evt)
        assert res.status_code == 400, f"Expected 400 for bypass pattern {idx}, got {res.status_code}"
        assert "Security validation failed" in res.get_json()["error"]


def test_issue9_suspicious_high_entropy_token_rejected(client):
    """Test 7: Suspicious high-entropy credential-like value where appropriate is rejected."""
    high_entropy_secret = "4fK9mP2xL5vR8qW1zT4bY7nC0jM3A9sD"

    # In endpoint
    evt1 = {
        "event_id": "evt-issue9-entropy-1",
        "event_type": "token_used",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-test",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "endpoint": f"/api/v1/auth/{high_entropy_secret}",
        "device_id": "device-1",
        "result": "accepted"
    }
    res1 = client.post("/events", json=evt1)
    assert res1.status_code == 400
    assert "Security validation failed" in res1.get_json()["error"]

    # In device_id
    evt2 = {
        "event_id": "evt-issue9-entropy-2",
        "event_type": "token_used",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-test",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": f"device-{high_entropy_secret}",
        "result": "accepted"
    }
    res2 = client.post("/events", json=evt2)
    assert res2.status_code == 400
    assert "Security validation failed" in res2.get_json()["error"]


def test_issue9_valid_hash_values_accepted(client):
    """Test 8: Valid hash values are accepted."""
    valid_hashes = [
        # 12-char hex (collector test format)
        "a4d3b8f1c29e",
        # 16-char hex (ip_hash format)
        "f3b29c9e8d1a2b3c",
        # 64-char hex (HMAC-SHA256 format from demo-app)
        "a4d3b8f1c201a4d3b8f1c201a4d3b8f1c201a4d3b8f1c201a4d3b8f1c2011234",
        # 'hash_' + 12 hex chars (simulator synthetic dataset format)
        "hash_6a438e0305c7"
    ]
    for idx, vhash in enumerate(valid_hashes):
        evt = {
            "event_id": f"evt-issue9-valid-hash-{idx}",
            "event_type": "token_issued",
            "time": "2026-08-07T12:20:00Z",
            "user_id": "user-test",
            "token_hash": vhash,
            "token_family": "family-xyz",
            "ip_hash": "f3b29c9e8d1a",
            "device_id": "device-1",
            "result": "accepted"
        }
        res = client.post("/events", json=evt)
        assert res.status_code == 201, f"Expected 201 for valid hash {vhash}, got {res.status_code}: {res.get_data(as_text=True)}"
        assert res.get_json()["status"] == "event persisted"


def test_issue9_valid_normal_event_without_credentials_accepted(client):
    """Test 9: Valid normal event without credentials is accepted."""
    evt = {
        "event_id": "evt-issue9-normal-event",
        "event_type": "token_issued",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-99",
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "device_id": "device-macos-1",
        "user_agent_family": "Chrome",
        "endpoint": "/api/v1/tokens/issue",
        "country": "US",
        "result": "accepted"
    }
    res = client.post("/events", json=evt)
    assert res.status_code == 201
    assert res.get_json()["status"] == "event persisted"


def test_issue9_rejected_credentials_never_reach_persistence(client):
    """Test 10: Confirm rejected credentials never reach the persistence/database layer."""
    unique_secret = "SecTok_4fK9mP2xL5vR8qW1zT4bY7nC0jM3A"
    bad_event_id = "evt-issue9-persistence-leak-test"

    bad_event = {
        "event_id": bad_event_id,
        "event_type": "token_issued",
        "time": "2026-08-07T12:20:00Z",
        "user_id": "user-test",
        "token_hash": RAW_TEST_JWT,
        "token_family": "family-xyz",
        "ip_hash": "f3b29c9e8d1a",
        "endpoint": f"/api/v1/auth?token={unique_secret}",
        "device_id": "device-1",
        "result": "accepted"
    }

    res = client.post("/events", json=bad_event)
    assert res.status_code == 400

    # Query the database directly to confirm nothing was persisted
    db = get_session()
    try:
        persisted_event = db.query(Event).filter(Event.event_id == bad_event_id).first()
        assert persisted_event is None, "Rejected event was persisted in the database!"

        all_events = db.query(Event).all()
        for ev in all_events:
            assert ev.event_id != bad_event_id
            assert RAW_TEST_JWT not in (ev.token_hash or "")
            assert RAW_TEST_JWT not in (ev.parent_token_hash or "")
            assert RAW_TEST_JWT not in (ev.endpoint or "")
            assert unique_secret not in (ev.endpoint or "")
    finally:
        db.close()





