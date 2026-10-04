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
        client.environ_base = {"HTTP_AUTHORIZATION": "Bearer tokenline-admin-secret"}
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
        "token_hash": "a4d3b8f1c29e",
        "token_family": "family-test",
        "ip_hash": "f3b29c9e8d1a",
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
        "token_hash": "a4d3b8f1c201",
        "token_family": "fam-1",
        "ip_hash": "f3b29c9e8d01",
        "device_id": "dev1",
        "result": "accepted"
    })
    client.post("/events", json={
        "event_id": "e2",
        "event_type": "token_refreshed",
        "time": "2026-08-16T10:10:00Z",
        "user_id": "u1",
        "token_hash": "a4d3b8f1c202",
        "parent_token_hash": "a4d3b8f1c201",
        "ip_hash": "f3b29c9e8d01",
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
    assert detail["chain"] == ["a4d3b8f1c201", "a4d3b8f1c202"]


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


def test_pagination_negative_and_upper_bound_limits(client):
    # Ingest 3 events
    for i in range(3):
        client.post("/events", json={
            "event_id": f"evt-page-{i}",
            "event_type": "token_issued",
            "time": f"2026-08-16T10:0{i}:00Z",
            "user_id": f"user-page-{i}",
            "token_hash": f"a4d3b8f1c29{i}",
            "token_family": "fam-page",
            "ip_hash": "f3b29c9e8d1a",
            "device_id": "dev-page",
            "result": "accepted"
        })

    # Test limit=-1 (safe handling: must not disable pagination or cause unbounded query)
    res_neg = client.get("/api/events?limit=-1")
    assert res_neg.status_code == 200
    events_neg = res_neg.get_json()
    assert len(events_neg) <= 100

    res_neg_events = client.get("/events?limit=-1")
    assert res_neg_events.status_code == 200
    assert len(res_neg_events.get_json()) <= 100

    # Test limit=999999999 (hard upper bound of 100)
    res_large = client.get("/api/events?limit=999999999")
    assert res_large.status_code == 200
    events_large = res_large.get_json()
    assert len(events_large) <= 100

    res_large_events = client.get("/events?limit=999999999")
    assert res_large_events.status_code == 200
    assert len(res_large_events.get_json()) <= 100


def test_pagination_across_all_collection_endpoints(client):
    # /api/scenarios with pagination limit=2, offset=0
    res_scenarios_p1 = client.get("/api/scenarios?limit=2&offset=0")
    assert res_scenarios_p1.status_code == 200
    scenarios_p1 = res_scenarios_p1.get_json()
    assert len(scenarios_p1) == 2

    # /api/scenarios with pagination limit=2, offset=2
    res_scenarios_p2 = client.get("/api/scenarios?limit=2&offset=2")
    assert res_scenarios_p2.status_code == 200
    scenarios_p2 = res_scenarios_p2.get_json()
    assert len(scenarios_p2) == 2
    assert scenarios_p1[0]["id"] != scenarios_p2[0]["id"]

    # /api/scenarios with limit=-1 and limit=999999999
    res_scenarios_neg = client.get("/api/scenarios?limit=-1")
    assert res_scenarios_neg.status_code == 200
    assert len(res_scenarios_neg.get_json()) <= 100

    res_scenarios_bound = client.get("/api/scenarios?limit=999999999")
    assert res_scenarios_bound.status_code == 200
    assert len(res_scenarios_bound.get_json()) <= 100

    # /api/families with limit=-1 and limit=999999999
    res_fam_neg = client.get("/api/families?limit=-1")
    assert res_fam_neg.status_code == 200
    res_fam_bound = client.get("/api/families?limit=999999999")
    assert res_fam_bound.status_code == 200

    # /api/reuse-records with limit=-1 and limit=999999999
    res_reuse_neg = client.get("/api/reuse-records?limit=-1")
    assert res_reuse_neg.status_code == 200
    res_reuse_bound = client.get("/api/reuse-records?limit=999999999")
    assert res_reuse_bound.status_code == 200


def test_path_parameter_maximum_lengths(client):
    # family_id > 128 chars rejected with 400
    long_family_id = "f" * 129
    res = client.get(f"/api/families/{long_family_id}")
    assert res.status_code == 400
    assert "exceeds maximum allowed length" in res.get_json().get("error", "")

    # scenario_name > 64 chars rejected with 400
    long_scenario_name = "s" * 65
    res2 = client.post(f"/api/scenarios/{long_scenario_name}/run")
    assert res2.status_code == 400
    assert "exceeds maximum allowed length" in res2.get_json().get("error", "")


def test_scenario_run_correlation_failure_is_not_silent_success(client, monkeypatch, caplog):
    import logging
    import sys

    def failing_process_event(evt, db_sess):
        raise RuntimeError("Correlator failure during scenario batch")

    collector_mod = sys.modules["backend.collector.app"]
    monkeypatch.setattr(collector_mod, "process_event", failing_process_event)

    with caplog.at_level(logging.ERROR, logger="tokenline.collector"):
        res = client.post("/api/scenarios/replay/run")

    assert res.status_code == 500
    assert res.get_json().get("error") == "Correlation error"
    assert "Correlator failure during scenario batch" in caplog.text


def test_unauthenticated_requests_rejected_on_all_frontend_api_endpoints(client):
    unauth_headers = {"Authorization": ""}

    # 1. Unauthenticated requests to all collection/detail endpoints return 401
    endpoints = [
        ("GET", "/api/events"),
        ("GET", "/api/families"),
        ("GET", "/api/families/fam-test"),
        ("GET", "/api/reuse-records"),
        ("GET", "/api/scenarios"),
        ("POST", "/api/scenarios/replay/run")
    ]

    for method, path in endpoints:
        if method == "GET":
            res = client.get(path, headers=unauth_headers)
        else:
            res = client.post(path, headers=unauth_headers)
        assert res.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {res.status_code}"
        assert res.get_json()["error"] == "Unauthorized"

    # 2. Invalid credentials return 401
    bad_headers = {"Authorization": "Bearer bad-token"}
    res_bad = client.get("/api/events", headers=bad_headers)
    assert res_bad.status_code == 401
    assert res_bad.get_json()["error"] == "Unauthorized"


def test_scenario_run_privilege_boundaries(client):
    # Specifically test POST /api/scenarios/<name>/run
    # 1. Without authentication -> 401
    res_unauth = client.post("/api/scenarios/replay/run", headers={"Authorization": ""})
    assert res_unauth.status_code == 401
    assert res_unauth.get_json()["error"] == "Unauthorized"

    # 2. Authenticated user with read-only role (insufficient privilege) -> 403
    read_headers = {"Authorization": "Bearer tokenline-read-secret"}
    res_read = client.post("/api/scenarios/replay/run", headers=read_headers)
    assert res_read.status_code == 403
    assert res_read.get_json()["error"] == "Forbidden"

    # 3. Authenticated client with ingest role (insufficient privilege for scenario execution) -> 403
    ingest_headers = {"Authorization": "Bearer tokenline-ingest-secret"}
    res_ingest = client.post("/api/scenarios/replay/run", headers=ingest_headers)
    assert res_ingest.status_code == 403
    assert res_ingest.get_json()["error"] == "Forbidden"

    # 4. Authenticated user with proper admin privilege -> 200 (allowed to reach existing logic)
    admin_headers = {"Authorization": "Bearer tokenline-admin-secret"}
    res_admin = client.post("/api/scenarios/replay/run", headers=admin_headers)
    assert res_admin.status_code == 200
    run_data = res_admin.get_json()
    assert run_data["scenario"] == "replay"
    assert run_data["event_count"] >= 3


def test_authenticated_read_endpoints_allowed_for_read_role(client):
    read_headers = {"Authorization": "Bearer tokenline-read-secret"}

    res_events = client.get("/api/events", headers=read_headers)
    assert res_events.status_code == 200

    res_families = client.get("/api/families", headers=read_headers)
    assert res_families.status_code == 200

    res_reuse = client.get("/api/reuse-records", headers=read_headers)
    assert res_reuse.status_code == 200

    res_scenarios = client.get("/api/scenarios", headers=read_headers)
    assert res_scenarios.status_code == 200


