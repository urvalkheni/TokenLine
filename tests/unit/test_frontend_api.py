import os
import sys
import pytest
import tempfile
import json
import logging
from unittest.mock import patch

# Add collector directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "backend", "collector"))

from app import app, MAX_PAGE_LIMIT, DEFAULT_PAGE_LIMIT
from db import init_db, get_session, Event, TokenFamilyMember, TokenReuseRecord


@pytest.fixture
def client():
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


def test_get_events_endpoint(client):
    # Ingest a sample event
    valid_event = {
        "event_id": "evt-api-test-1",
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
    client.post("/events", json=valid_event)

    response = client.get("/api/events")
    assert response.status_code == 200
    events = response.get_json()
    assert len(events) >= 1
    assert events[0]["event_id"] == "evt-api-test-1"


def test_get_families_endpoint(client):
    # Ingest rotation events
    client.post("/events", json={
        "event_id": "e1",
        "event_type": "token_issued",
        "time": "2026-08-16T10:00:00Z",
        "user_id": "u1",
        "token_hash": "t1",
        "token_family": "fam-1",
        "ip_hash": "ip1",
        "device_id": "dev1",
        "result": "accepted"
    })
    client.post("/events", json={
        "event_id": "e2",
        "event_type": "token_refreshed",
        "time": "2026-08-16T10:10:00Z",
        "user_id": "u1",
        "token_hash": "t2",
        "parent_token_hash": "t1",
        "ip_hash": "ip1",
        "device_id": "dev1",
        "result": "accepted"
    })

    response = client.get("/api/families")
    assert response.status_code == 200
    families = response.get_json()
    assert "fam-1" in families
    assert len(families["fam-1"]) == 2

    # Test family detail
    detail_res = client.get("/api/families/fam-1")
    assert detail_res.status_code == 200
    detail = detail_res.get_json()
    assert detail["token_family"] == "fam-1"
    assert len(detail["tokens"]) == 2
    assert detail["chain"] == ["t1", "t2"]


def test_get_scenarios_and_run(client):
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    scenarios = res.get_json()
    assert len(scenarios) == 5
    scenario_ids = [s["id"] for s in scenarios]
    assert "refresh-reuse" in scenario_ids
    assert "replay" in scenario_ids

    # Run replay scenario via API
    run_res = client.post("/api/scenarios/replay/run")
    assert run_res.status_code == 200
    run_data = run_res.get_json()
    assert run_data["scenario"] == "replay"
    assert run_data["event_count"] >= 3


def test_frontend_static_serving(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"TokenLine" in res.data


def test_family_id_param_max_length(client):
    """Endpoint parameter family_id exceeding maximum length is rejected."""
    oversized_family_id = "f" * 129
    response = client.get(f"/api/families/{oversized_family_id}")
    assert response.status_code == 400
    assert "maximum allowed length" in response.get_json().get("error", "")


def test_pagination_negative_limit_safe(client):
    """
    limit=-1 must be handled safely and must not result in an unbounded dataset
    or disable pagination.
    """
    db = get_session()
    for i in range(150):
        db.add(Event(
            event_id=f"evt-{i:03d}",
            event_type="token_issued",
            time=f"2026-08-16T10:{i % 60:02d}:00Z",
            user_id="user-1",
            token_hash=f"tok-{i}",
            ip_hash="ip-1",
            device_id="dev-1",
            result="accepted"
        ))
    db.commit()
    db.close()

    response = client.get("/events?limit=-1")
    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == DEFAULT_PAGE_LIMIT
    assert len(data) <= MAX_PAGE_LIMIT

    api_res = client.get("/api/events?limit=-1")
    assert api_res.status_code == 200
    assert len(api_res.get_json()) == DEFAULT_PAGE_LIMIT


def test_pagination_hard_upper_bound_limit(client):
    """
    limit=999999999 must not return an unbounded dataset and is capped at MAX_PAGE_LIMIT.
    """
    db = get_session()
    for i in range(150):
        db.add(Event(
            event_id=f"evt-huge-{i:03d}",
            event_type="token_issued",
            time=f"2026-08-16T10:{i % 60:02d}:00Z",
            user_id="user-1",
            token_hash=f"tok-huge-{i}",
            ip_hash="ip-1",
            device_id="dev-1",
            result="accepted"
        ))
    db.commit()
    db.close()

    response = client.get("/events?limit=999999999")
    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == MAX_PAGE_LIMIT


def test_pagination_all_collection_endpoints(client):
    """Pagination for all collection endpoints: /api/families, /api/reuse-records, /api/scenarios."""
    db = get_session()
    for i in range(120):
        db.add(TokenFamilyMember(
            token_hash=f"hash-{i}",
            token_family=f"fam-{i:03d}",
            is_rotated=False,
            user_id="u1"
        ))
    for i in range(120):
        db.add(TokenReuseRecord(
            token_hash=f"reuse-hash-{i}",
            token_family=f"fam-{i:03d}",
            reused_at="2026-08-16T10:00:00Z",
            attempted_event_id=f"evt-{i}"
        ))
    db.commit()
    db.close()

    # /api/families with limit=999999999
    res_fam_huge = client.get("/api/families?limit=999999999")
    assert res_fam_huge.status_code == 200
    fam_data = res_fam_huge.get_json()
    assert len(fam_data) <= MAX_PAGE_LIMIT
    assert len(fam_data) == 100

    # /api/families with limit=-1
    res_fam_neg = client.get("/api/families?limit=-1")
    assert res_fam_neg.status_code == 200
    assert len(res_fam_neg.get_json()) == DEFAULT_PAGE_LIMIT

    # /api/reuse-records with limit=999999999
    res_reuse_huge = client.get("/api/reuse-records?limit=999999999")
    assert res_reuse_huge.status_code == 200
    assert len(res_reuse_huge.get_json()) == MAX_PAGE_LIMIT

    # /api/reuse-records with limit=-1
    res_reuse_neg = client.get("/api/reuse-records?limit=-1")
    assert res_reuse_neg.status_code == 200
    assert len(res_reuse_neg.get_json()) == DEFAULT_PAGE_LIMIT

    # /api/scenarios with pagination
    res_scenarios = client.get("/api/scenarios?limit=2&offset=1")
    assert res_scenarios.status_code == 200
    scenarios_data = res_scenarios.get_json()
    assert len(scenarios_data) == 2


def test_scenario_run_correlation_failure_not_silent(client, caplog):
    """When persistence or correlation fails during scenario run, it is logged and fails cleanly."""
    with patch("app.process_event", side_effect=RuntimeError("Correlator breakdown")):
        with caplog.at_level(logging.ERROR):
            response = client.post("/api/scenarios/replay/run")

        assert response.status_code == 500
        res_data = response.get_json()
        assert "Correlation error" in res_data.get("error", "")
        assert any("Correlation failed during scenario 'replay'" in record.message for record in caplog.records)
