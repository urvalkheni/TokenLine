import os
import sqlite3
from datetime import datetime, timezone
from sqlalchemy import text, inspect


class MigrationManager:
    """
    Manages database schema migrations for TokenLine.
    Supports both SQLite and PostgreSQL backends with forward upgrades and rollbacks.
    """

    def __init__(self, engine):
        self.engine = engine
        self._ensure_migration_table()

    def _ensure_migration_table(self):
        with self.engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version VARCHAR(64) PRIMARY KEY,
                    applied_at VARCHAR(64) NOT NULL
                )
            """))

    def get_applied_migrations(self):
        with self.engine.connect() as conn:
            result = conn.execute(text("SELECT version FROM schema_migrations ORDER BY version ASC"))
            return [row[0] for row in result.fetchall()]

    def record_migration(self, version):
        with self.engine.begin() as conn:
            now_str = datetime.now(timezone.utc).isoformat()
            conn.execute(
                text("INSERT INTO schema_migrations (version, applied_at) VALUES (:version, :applied_at)"),
                {"version": version, "applied_at": now_str}
            )

    def remove_migration(self, version):
        with self.engine.begin() as conn:
            conn.execute(
                text("DELETE FROM schema_migrations WHERE version = :version"),
                {"version": version}
            )

    def apply_all(self):
        """Applies all pending migrations in order."""
        applied = set(self.get_applied_migrations())
        for version, (upgrade_fn, _) in MIGRATIONS.items():
            if version not in applied:
                with self.engine.begin() as conn:
                    upgrade_fn(conn, self.engine)
                self.record_migration(version)

    def rollback_to(self, target_version: str):
        """Rolls back applied migrations down to target_version (exclusive)."""
        applied = self.get_applied_migrations()
        for version in reversed(applied):
            if version > target_version:
                _, downgrade_fn = MIGRATIONS.get(version, (None, None))
                if downgrade_fn:
                    with self.engine.begin() as conn:
                        downgrade_fn(conn, self.engine)
                self.remove_migration(version)


# --- MIGRATION DEFINITIONS ---

def upgrade_001(conn, engine):
    """Initial schema migration: tables creation if not exist."""
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS events (
            event_id VARCHAR PRIMARY KEY,
            event_type VARCHAR NOT NULL,
            time VARCHAR NOT NULL,
            user_id VARCHAR NOT NULL,
            token_hash VARCHAR,
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
        CREATE TABLE IF NOT EXISTS token_family_members (
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
        CREATE TABLE IF NOT EXISTS token_reuse_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash VARCHAR NOT NULL,
            token_family VARCHAR NOT NULL,
            reused_at VARCHAR NOT NULL,
            attempted_event_id VARCHAR NOT NULL
        )
    """))


def downgrade_001(conn, engine):
    conn.execute(text("DROP TABLE IF EXISTS token_reuse_records"))
    conn.execute(text("DROP TABLE IF EXISTS token_family_members"))
    conn.execute(text("DROP TABLE IF EXISTS events"))


def upgrade_002(conn, engine):
    """Add indexes and uniqueness constraints."""
    # 1. Indexes on events
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_time ON events (time)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_user_id ON events (user_id)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_token_family ON events (token_family)"))

    # 2. Indexes on token_family_members
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_token_family_members_token_family ON token_family_members (token_family)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_token_family_members_user_id ON token_family_members (user_id)"))

    # 3. Index & Uniqueness constraint on token_reuse_records
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_token_reuse_records_token_hash ON token_reuse_records (token_hash)"))
    conn.execute(text("""
        DELETE FROM token_reuse_records 
        WHERE id NOT IN (
            SELECT MIN(id) 
            FROM token_reuse_records 
            GROUP BY token_hash, attempted_event_id
        )
    """))
    conn.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_token_reuse_event 
        ON token_reuse_records (token_hash, attempted_event_id)
    """))


def downgrade_002(conn, engine):
    conn.execute(text("DROP INDEX IF EXISTS uq_token_reuse_event"))
    conn.execute(text("DROP INDEX IF EXISTS ix_token_reuse_records_token_hash"))
    conn.execute(text("DROP INDEX IF EXISTS ix_token_family_members_user_id"))
    conn.execute(text("DROP INDEX IF EXISTS ix_token_family_members_token_family"))
    conn.execute(text("DROP INDEX IF EXISTS ix_events_token_family"))
    conn.execute(text("DROP INDEX IF EXISTS ix_events_user_id"))
    conn.execute(text("DROP INDEX IF EXISTS ix_events_time"))


def upgrade_003(conn, engine):
    """Migrates existing legacy timestamp strings into normalized UTC ISO-8601 strings."""
    # Normalize events.time
    try:
        rows = conn.execute(text("SELECT event_id, time FROM events")).fetchall()
        for eid, tval in rows:
            if tval:
                try:
                    s = tval.strip()
                    if s.endswith("Z"):
                        s = s[:-1] + "+00:00"
                    dt = datetime.fromisoformat(s)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    else:
                        dt = dt.astimezone(timezone.utc)
                    norm = dt.isoformat().replace("+00:00", "Z")
                    conn.execute(
                        text("UPDATE events SET time = :norm WHERE event_id = :eid"),
                        {"norm": norm, "eid": eid}
                    )
                except Exception:
                    pass
    except Exception:
        pass


def downgrade_003(conn, engine):
    # Data normalization is preserved
    pass


def upgrade_004(conn, engine):
    """Add schema_version, source, and is_simulation columns to events table."""
    try:
        inspector = inspect(engine)
        cols = [c["name"] for c in inspector.get_columns("events")]
    except Exception:
        cols = []

    if "schema_version" not in cols:
        try:
            conn.execute(text("ALTER TABLE events ADD COLUMN schema_version VARCHAR"))
        except Exception:
            pass
    if "source" not in cols:
        try:
            conn.execute(text("ALTER TABLE events ADD COLUMN source VARCHAR"))
        except Exception:
            pass
    if "is_simulation" not in cols:
        try:
            conn.execute(text("ALTER TABLE events ADD COLUMN is_simulation BOOLEAN DEFAULT 0"))
        except Exception:
            pass


def downgrade_004(conn, engine):
    pass


def upgrade_005(conn, engine):
    """Create scenario_executions table for atomic execution tracking."""
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS scenario_executions (
            id VARCHAR PRIMARY KEY,
            scenario_name VARCHAR NOT NULL,
            started_at VARCHAR NOT NULL,
            completed_at VARCHAR,
            status VARCHAR NOT NULL,
            event_count INTEGER DEFAULT 0,
            error_message VARCHAR
        )
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scenario_executions_scenario_name ON scenario_executions (scenario_name)"))


def downgrade_005(conn, engine):
    conn.execute(text("DROP INDEX IF EXISTS ix_scenario_executions_scenario_name"))
    conn.execute(text("DROP TABLE IF EXISTS scenario_executions"))


MIGRATIONS = {
    "001_initial_schema": (upgrade_001, downgrade_001),
    "002_add_indexes_and_constraints": (upgrade_002, downgrade_002),
    "003_convert_timestamps_to_timezone_aware": (upgrade_003, downgrade_003),
    "004_canonical_schema_fields": (upgrade_004, downgrade_004),
    "005_scenario_executions": (upgrade_005, downgrade_005),
}


def run_migrations(engine=None):
    """Helper to run all migrations against engine."""
    if engine is None:
        from backend.collector.db import get_engine
        engine = get_engine()
    mgr = MigrationManager(engine)
    mgr.apply_all()
    return mgr

