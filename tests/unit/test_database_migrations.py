import os
import tempfile
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from backend.collector.db import Base, Event, TokenFamilyMember, TokenReuseRecord, init_db, get_session, insert_event
from backend.database.migrations import MigrationManager, run_migrations


@pytest.fixture
def fresh_db_engine():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    
    yield engine

    engine.dispose()
    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass


def test_fresh_database_and_required_indexes(fresh_db_engine):
    # Run init_db which creates tables and applies migrations
    init_db()

    inspector = inspect(fresh_db_engine)

    # 1. Verify tables exist
    tables = inspector.get_table_names()
    assert "events" in tables
    assert "token_family_members" in tables
    assert "token_reuse_records" in tables
    assert "schema_migrations" in tables

    # 2. Verify indexes on events
    events_indexes = {ix["name"]: [col for col in ix["column_names"]] for ix in inspector.get_indexes("events")}
    events_cols_indexed = [col for cols in events_indexes.values() for col in cols]
    assert "time" in events_cols_indexed
    assert "user_id" in events_cols_indexed
    assert "token_family" in events_cols_indexed

    # 3. Verify indexes on token_family_members
    tfm_indexes = {ix["name"]: [col for col in ix["column_names"]] for ix in inspector.get_indexes("token_family_members")}
    tfm_cols_indexed = [col for cols in tfm_indexes.values() for col in cols]
    assert "token_family" in tfm_cols_indexed
    assert "user_id" in tfm_cols_indexed

    # 4. Verify indexes on token_reuse_records
    reuse_indexes = {ix["name"]: [col for col in ix["column_names"]] for ix in inspector.get_indexes("token_reuse_records")}
    reuse_cols_indexed = [col for cols in reuse_indexes.values() for col in cols]
    assert "token_hash" in reuse_cols_indexed


def test_duplicate_reuse_records_rejected_by_constraint(fresh_db_engine):
    init_db()
    SessionLocal = sessionmaker(bind=fresh_db_engine)
    session = SessionLocal()

    rec1 = TokenReuseRecord(
        token_hash="tok-dup-1",
        token_family="fam-dup",
        reused_at="2026-09-01T10:00:00Z",
        attempted_event_id="evt-dup-attempt"
    )
    session.add(rec1)
    session.commit()

    # Attempting to insert identical (token_hash, attempted_event_id)
    rec2 = TokenReuseRecord(
        token_hash="tok-dup-1",
        token_family="fam-dup",
        reused_at="2026-09-01T10:05:00Z",
        attempted_event_id="evt-dup-attempt"
    )
    session.add(rec2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    session.close()


def test_timestamp_queries_across_timezone_offsets(fresh_db_engine):
    init_db()
    SessionLocal = sessionmaker(bind=fresh_db_engine)
    session = SessionLocal()

    # Ingest events with different timezone offsets
    # e1: 12:00:00 UTC
    e1 = Event(
        event_id="ev-tz-utc",
        event_type="token_issued",
        time="2026-08-07T12:00:00Z",
        user_id="u-tz",
        token_hash="tok-1",
        ip_hash="ip",
        device_id="dev",
        result="accepted"
    )
    # e2: 17:30:00 +05:30 (equivalent to 12:00:00 UTC)
    e2 = Event(
        event_id="ev-tz-ist-same",
        event_type="token_used",
        time="2026-08-07T17:30:00+05:30",
        user_id="u-tz",
        token_hash="tok-1",
        ip_hash="ip",
        device_id="dev",
        result="accepted"
    )
    # e3: 07:00:00 -04:00 (equivalent to 11:00:00 UTC, earlier than e1)
    e3 = Event(
        event_id="ev-tz-earlier",
        event_type="token_issued",
        time="2026-08-07T07:00:00-04:00",
        user_id="u-tz",
        token_hash="tok-0",
        ip_hash="ip",
        device_id="dev",
        result="accepted"
    )
    # e4: 18:00:00 +05:30 (equivalent to 12:30:00 UTC, later than e1)
    e4 = Event(
        event_id="ev-tz-later",
        event_type="token_used",
        time="2026-08-07T18:00:00+05:30",
        user_id="u-tz",
        token_hash="tok-1",
        ip_hash="ip",
        device_id="dev",
        result="accepted"
    )

    session.add_all([e1, e2, e3, e4])
    session.commit()

    # 1. Query chronological order ascending
    ordered = session.query(Event).order_by(Event.time.asc()).all()
    ordered_ids = [e.event_id for e in ordered]
    assert ordered_ids[0] == "ev-tz-earlier"
    assert ordered_ids[3] == "ev-tz-later"

    # 2. Range query using UTC threshold
    cutoff = datetime(2026, 8, 7, 12, 15, tzinfo=timezone.utc)
    after_cutoff = session.query(Event).filter(Event.time > cutoff).all()
    assert len(after_cutoff) == 1
    assert after_cutoff[0].event_id == "ev-tz-later"

    session.close()


def test_migration_on_existing_database_and_rollback(fresh_db_engine):
    # Simulate an existing legacy database created with raw unindexed tables
    with fresh_db_engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE events (
                event_id VARCHAR PRIMARY KEY,
                event_type VARCHAR NOT NULL,
                time VARCHAR NOT NULL,
                user_id VARCHAR NOT NULL,
                token_hash VARCHAR NOT NULL,
                token_family VARCHAR,
                parent_token_hash VARCHAR,
                ip_hash VARCHAR NOT NULL,
                country VARCHAR,
                device_id VARCHAR NOT NULL,
                user_agent_family VARCHAR,
                endpoint VARCHAR,
                result VARCHAR NOT NULL
            )
        """))
        conn.execute(text("""
            CREATE TABLE token_family_members (
                token_hash VARCHAR PRIMARY KEY,
                token_family VARCHAR NOT NULL,
                parent_token_hash VARCHAR,
                is_rotated BOOLEAN NOT NULL DEFAULT 0,
                rotated_at VARCHAR,
                superseded_by VARCHAR,
                user_id VARCHAR NOT NULL
            )
        """))
        conn.execute(text("""
            CREATE TABLE token_reuse_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash VARCHAR NOT NULL,
                token_family VARCHAR NOT NULL,
                reused_at VARCHAR NOT NULL,
                attempted_event_id VARCHAR NOT NULL
            )
        """))
        # Insert legacy event with non-UTC offset string
        conn.execute(text("""
            INSERT INTO events (event_id, event_type, time, user_id, token_hash, ip_hash, device_id, result)
            VALUES ('e-legacy-1', 'token_issued', '2026-08-07T17:30:00+05:30', 'u-leg', 'tok-leg', 'ip', 'dev', 'accepted')
        """))

    # Execute migration on the existing legacy database
    mgr = run_migrations(fresh_db_engine)
    applied = mgr.get_applied_migrations()
    assert "001_initial_schema" in applied
    assert "002_add_indexes_and_constraints" in applied
    assert "003_convert_timestamps_to_timezone_aware" in applied

    # Verify legacy timestamp was normalized to UTC
    with fresh_db_engine.connect() as conn:
        row = conn.execute(text("SELECT time FROM events WHERE event_id = 'e-legacy-1'")).fetchone()
        assert row[0] == "2026-08-07T12:00:00Z"

    # Test rollback of migration 002
    mgr.rollback_to("001_initial_schema")
    applied_after_rollback = mgr.get_applied_migrations()
    assert applied_after_rollback == ["001_initial_schema"]
