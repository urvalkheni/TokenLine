import os
from sqlalchemy import create_engine, Column, String, Boolean, Integer, event
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class Event(Base):
    __tablename__ = "events"

    event_id = Column(String, primary_key=True)
    event_type = Column(String, nullable=False)
    time = Column(String, nullable=False)
    user_id = Column(String, nullable=False)
    token_hash = Column(String, nullable=False)
    token_family = Column(String, nullable=True)
    parent_token_hash = Column(String, nullable=True)
    ip_hash = Column(String, nullable=False)
    country = Column(String, nullable=True)
    device_id = Column(String, nullable=False)
    user_agent_family = Column(String, nullable=True)
    endpoint = Column(String, nullable=True)
    result = Column(String, nullable=False)

class TokenFamilyMember(Base):
    __tablename__ = "token_family_members"

    token_hash = Column(String, primary_key=True)
    token_family = Column(String, nullable=False)
    parent_token_hash = Column(String, nullable=True)
    is_rotated = Column(Boolean, default=False, nullable=False)
    rotated_at = Column(String, nullable=True)
    superseded_by = Column(String, nullable=True)
    user_id = Column(String, nullable=False)

class TokenReuseRecord(Base):
    __tablename__ = "token_reuse_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_hash = Column(String, nullable=False)
    token_family = Column(String, nullable=False)
    reused_at = Column(String, nullable=False)
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
            @event.listens_for(_engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode = MEMORY")
                cursor.close()
        else:
            _engine = create_engine(db_url)
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    return _engine

def get_session():
    get_engine()
    return _SessionLocal()

def init_db():
    Base.metadata.create_all(bind=get_engine())

def insert_event(event_data):
    db = get_session()
    try:
        existing = db.query(Event).filter(Event.event_id == event_data["event_id"]).first()
        if existing:
            return existing, False

        db_event = Event(
            event_id=event_data["event_id"],
            event_type=event_data["event_type"],
            time=event_data["time"],
            user_id=event_data["user_id"],
            token_hash=event_data["token_hash"],
            token_family=event_data.get("token_family"),
            parent_token_hash=event_data.get("parent_token_hash"),
            ip_hash=event_data["ip_hash"],
            country=event_data.get("country"),
            device_id=event_data["device_id"],
            user_agent_family=event_data.get("user_agent_family"),
            endpoint=event_data.get("endpoint"),
            result=event_data["result"]
        )
        db.add(db_event)
        db.commit()
        return db_event, True
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

