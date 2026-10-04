import os
import sys
import pytest
import tempfile
import json

from backend.collector.app import app
from backend.collector.db import init_db, get_session, Event, TokenFamilyMember, TokenReuseRecord



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
