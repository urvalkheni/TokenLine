import os
import json
from typing import Dict, Any, List, Optional
from contextlib import contextmanager
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, String, Boolean, Integer, UniqueConstraint, Index
from sqlalchemy.types import TypeDecorator, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class TimezoneAwareDateTime(TypeDecorator):
    """
    SQLAlchemy TypeDecorator that normalizes and stores all timestamps as UTC
    timezone-aware DateTime objects, accepting ISO 8601 strings, short time strings,
    or datetime objects, and returning ISO 8601 UTC strings formatted as 'YYYY-MM-DDTHH:MM:SSZ'.
    Ensures correct chronological ordering and range filtering across different timezone offsets.
    """
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, str):
            s = value.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(s)
            except Exception:
                try:
                    # Handle HH:MM or HH:MM:SS short fixture strings
                    t = datetime.strptime(s, "%H:%M:%S" if s.count(":") == 2 else "%H:%M").time()
                    dt = datetime.combine(datetime(2026, 1, 1).date(), t, tzinfo=timezone.utc)
                except Exception:
                    dt = datetime.now(timezone.utc)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt
        elif isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                dt = value.replace(tzinfo=timezone.utc)
            else:
                dt = value.astimezone(timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        if isinstance(value, str):
            return value
        return value


class Event(Base):
    __tablename__ = "events"

    event_id = Column(String, primary_key=True)
    event_type = Column(String, nullable=False)
    time = Column(TimezoneAwareDateTime, nullable=False, index=True)
    user_id = Column(String, nullable=False, index=True)
    token_hash = Column(String, nullable=True)
    token_family = Column(String, nullable=True, index=True)
    parent_token_hash = Column(String, nullable=True)
    ip_hash = Column(String, nullable=False)
    country = Column(String, nullable=True)
    device_id = Column(String, nullable=False)
    user_agent_family = Column(String, nullable=True)
    endpoint = Column(String, nullable=True)
    result = Column(String, nullable=False)
    schema_version = Column(String, nullable=True)
    source = Column(String, nullable=True)
    is_simulation = Column(Boolean, nullable=True, default=False)


class TokenFamilyMember(Base):
    __tablename__ = "token_family_members"

    token_hash = Column(String, primary_key=True)
    token_family = Column(String, nullable=False, index=True)
    parent_token_hash = Column(String, nullable=True)
    is_rotated = Column(Boolean, default=False, nullable=False)
    rotated_at = Column(TimezoneAwareDateTime, nullable=True)
    superseded_by = Column(String, nullable=True)
    user_id = Column(String, nullable=False, index=True)


class TokenReuseRecord(Base):
    __tablename__ = "token_reuse_records"
    __table_args__ = (
        UniqueConstraint("token_hash", "attempted_event_id", name="uq_token_reuse_event"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_hash = Column(String, nullable=False, index=True)
    token_family = Column(String, nullable=False)
    reused_at = Column(TimezoneAwareDateTime, nullable=False)
    attempted_event_id = Column(String, nullable=False)


class ScenarioExecution(Base):
    __tablename__ = "scenario_executions"

    id = Column(String, primary_key=True)
    scenario_name = Column(String, nullable=False, index=True)
    started_at = Column(TimezoneAwareDateTime, nullable=False)
    completed_at = Column(TimezoneAwareDateTime, nullable=True)
    status = Column(String, nullable=False)  # "running", "success", "failed"
    event_count = Column(Integer, default=0)
    error_message = Column(String, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("dedup_fingerprint", name="uq_alerts_dedup"),
    )

    id = Column(String, primary_key=True)
    rule_id = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False, default="open", index=True)
    timestamp = Column(TimezoneAwareDateTime, nullable=False, index=True)
    title = Column(String, nullable=False)
    explanation = Column(String, nullable=False)
    event_refs_json = Column(String, nullable=False)  # JSON-encoded array of event_id strings
    token_family_id = Column(String, nullable=True, index=True)
    token_hash = Column(String, nullable=True, index=True)
    user_id = Column(String, nullable=True, index=True)
    evidence_json = Column(String, nullable=False)    # JSON-encoded dictionary of evidence
    dedup_fingerprint = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(TimezoneAwareDateTime, nullable=False)
    updated_at = Column(TimezoneAwareDateTime, nullable=False)

    def to_dict(self) -> Dict[str, Any]:
        event_refs = []
        if self.event_refs_json:
            try:
                event_refs = json.loads(self.event_refs_json)
            except Exception:
                event_refs = []
        evidence = {}
        if self.evidence_json:
            try:
                evidence = json.loads(self.evidence_json)
            except Exception:
                evidence = {}

        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "status": self.status,
            "timestamp": self.timestamp,
            "title": self.title,
            "explanation": self.explanation,
            "event_refs": event_refs,
            "token_family_id": self.token_family_id,
            "token_hash": self.token_hash,
            "user_id": self.user_id,
            "evidence": evidence,
            "dedup_fingerprint": self.dedup_fingerprint,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


_engine = None
_cached_url = None
_SessionLocal = None


def get_engine():
    global _engine, _cached_url, _SessionLocal
    db_url = os.environ.get("DATABASE_URL", "sqlite:///./tokenline.db")
    
    # Ensure PostgreSQL connection string from Neon has sslmode=require if not present
    if db_url.startswith("postgresql") and "sslmode" not in db_url:
        separator = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{separator}sslmode=require"

    if _engine is None or _cached_url != db_url:
        _cached_url = db_url
        if db_url.startswith("sqlite"):
            _engine = create_engine(db_url, connect_args={"check_same_thread": False})
        else:
            _engine = create_engine(db_url)
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    return _engine


def get_session():
    get_engine()
    return _SessionLocal()


@contextmanager
def session_scope():
    """Provide a safe transactional scope around a series of database operations."""
    session = get_session()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db():
    """Initializes schema and runs all migrations."""
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    from backend.database.migrations import run_migrations
    run_migrations(engine)


def insert_event(event_data, session=None):
    """
    Inserts a canonical event into the database idempotently.
    If session is provided, stages insertion within the caller's active transaction (via session.flush()).
    If session is None, manages an isolated session with commit/rollback.
    """
    from sqlalchemy.exc import IntegrityError

    own_session = False
    if session is None:
        session = get_session()
        own_session = True

    try:
        # Idempotent insert: if event_id already exists, return existing record
        existing = session.query(Event).filter(Event.event_id == event_data["event_id"]).first()
        if existing:
            setattr(existing, "_is_new", False)
            return existing

        db_event = Event(
            event_id=event_data["event_id"],
            event_type=event_data["event_type"],
            time=event_data["time"],
            user_id=event_data["user_id"],
            token_hash=event_data.get("token_hash"),
            token_family=event_data.get("token_family"),
            parent_token_hash=event_data.get("parent_token_hash"),
            ip_hash=event_data["ip_hash"],
            country=event_data.get("country"),
            device_id=event_data["device_id"],
            user_agent_family=event_data.get("user_agent_family"),
            endpoint=event_data.get("endpoint"),
            result=event_data["result"],
            schema_version=event_data.get("schema_version"),
            source=event_data.get("source"),
            is_simulation=event_data.get("is_simulation", False),
        )
        session.add(db_event)
        if own_session:
            session.commit()
        else:
            session.flush()
        setattr(db_event, "_is_new", True)
        return db_event
    except IntegrityError as ie:
        if own_session:
            session.rollback()
            existing = session.query(Event).filter(Event.event_id == event_data["event_id"]).first()
            if existing:
                setattr(existing, "_is_new", False)
                return existing
        raise ie
    except Exception as e:
        if own_session:
            session.rollback()
        raise e
    finally:
        if own_session:
            session.close()
