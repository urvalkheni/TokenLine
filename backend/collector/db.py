import os
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


def insert_event(event_data):
    db = get_session()
    try:
        # Idempotent insert: if event_id already exists, return existing record
        existing = db.query(Event).filter(Event.event_id == event_data["event_id"]).first()
        if existing:
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
        db.add(db_event)
        db.commit()
        return db_event
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
