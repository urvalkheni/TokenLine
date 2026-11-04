from datetime import datetime, timezone
import importlib
import json
import logging

import pytest

from backend.collector import db as collector_db
from backend.collector.db import Event, TokenReuseRecord, get_session, init_db

collector_module = importlib.import_module("backend.collector.app")


def test_operational_log_formatter_emits_structured_generic_fields():
    record = logging.LogRecord("tokenline.collector", logging.ERROR, "app.py", 1,
                               "event storage failed", (), None)
    record.operation = "event_storage"
    record.error_type = "RuntimeError"
    formatted = collector_module.OperationalJsonFormatter().format(record)
    payload = json.loads(formatted)
    assert payload["message"] == "event storage failed"
    assert payload["operation"] == "event_storage"
    assert payload["error_type"] == "RuntimeError"
    assert payload["level"] == "ERROR"


@pytest.fixture
def operational_client(tmp_path, monkeypatch):
    database_path = tmp_path / "operations.sqlite"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database_path}")
    init_db()
    app = collector_module.create_app({"TESTING": True})
    return app.test_client()


def test_health_endpoint_is_live_without_database_access(monkeypatch):
    def fail_if_called():
        raise AssertionError("liveness must not depend on the database")

    monkeypatch.setattr(collector_module, "get_engine", fail_if_called)
    response = collector_module.create_app({"TESTING": True}).test_client().get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "healthy"}


def test_readiness_requires_database_and_initialized_schema(operational_client):
    response = operational_client.get("/ready")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ready"}


def test_readiness_returns_unavailable_when_database_fails(monkeypatch):
    monkeypatch.setattr(collector_module, "get_engine", lambda: (_ for _ in ()).throw(RuntimeError("db-secret")))
    response = collector_module.create_app({"TESTING": True}).test_client().get("/readiness")
    assert response.status_code == 503
    assert response.get_json() == {"status": "not_ready"}


def test_retention_deletes_expired_events_and_linked_reuse_records(operational_client):
    session = get_session()
    session.add_all([
        Event(event_id="expired-event", event_type="token_used", time="2020-01-01T00:00:00Z",
              user_id="user-a", ip_hash="0123456789ab", device_id="device-a", result="accepted"),
        Event(event_id="recent-event", event_type="token_used", time="2026-10-30T00:00:00Z",
              user_id="user-b", ip_hash="0123456789ab", device_id="device-b", result="accepted"),
        TokenReuseRecord(token_hash="abcdef012345", token_family="family-a",
                         reused_at="2020-01-01T00:00:00Z", attempted_event_id="expired-event"),
    ])
    session.commit()
    session.close()

    result = collector_db.delete_expired_events(30, now=datetime(2026, 11, 4, tzinfo=timezone.utc))
    assert result["deleted_events"] == 1
    assert result["deleted_reuse_records"] == 1

    session = get_session()
    try:
        assert session.query(Event.event_id).all() == [("recent-event",)]
        assert session.query(TokenReuseRecord).count() == 0
    finally:
        session.close()


@pytest.mark.parametrize("retention_days", [0, -1, "invalid", None])
def test_retention_requires_positive_integer(retention_days):
    with pytest.raises(ValueError):
        collector_db.delete_expired_events(retention_days)


def test_retention_setting_must_be_positive():
    with pytest.raises(ValueError, match="EVENT_RETENTION_DAYS"):
        collector_module.create_app({"TESTING": True, "EVENT_RETENTION_DAYS": 0})
