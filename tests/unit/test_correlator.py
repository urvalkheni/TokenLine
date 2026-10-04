import os
import sys
import pytest
import tempfile
import json

from backend.collector.db import init_db, get_session, TokenFamilyMember, TokenReuseRecord
from backend.correlator import process_event, reconstruct_chain




@pytest.fixture
def db_session():
    # Setup temporary database file
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    
    init_db()
    db = get_session()
    
    yield db

    db.close()
    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass

def test_normal_three_token_rotation(db_session):
    # Event 1: Issue token A
    process_event({
        "event_id": "evt-1",
        "event_type": "token_issued",
        "time": "2026-08-16T12:00:00Z",
        "user_id": "user-1",
        "token_hash": "token-A",
        "token_family": "family-1",
        "ip_hash": "ip-1",
        "device_id": "dev-1",
        "result": "accepted"
    }, db_session)

    # Event 2: Refresh token A to B
    process_event({
        "event_id": "evt-2",
        "event_type": "token_refreshed",
        "time": "2026-08-16T12:10:00Z",
        "user_id": "user-1",
        "token_hash": "token-B",
        "parent_token_hash": "token-A",
        "ip_hash": "ip-1",
        "device_id": "dev-1",
        "result": "accepted"
    }, db_session)

    # Event 3: Refresh token B to C
    process_event({
        "event_id": "evt-3",
        "event_type": "token_refreshed",
        "time": "2026-08-16T12:20:00Z",
        "user_id": "user-1",
        "token_hash": "token-C",
        "parent_token_hash": "token-B",
        "ip_hash": "ip-1",
        "device_id": "dev-1",
        "result": "accepted"
    }, db_session)

    # Verify database structures
    a = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == "token-A").first()
    b = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == "token-B").first()
    c = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == "token-C").first()

    assert a.is_rotated is True
    assert b.is_rotated is True
    assert c.is_rotated is False

    assert a.token_family == b.token_family == c.token_family
    assert b.parent_token_hash == "token-A"
    assert c.parent_token_hash == "token-B"

    # Verify reconstruction
    chain = reconstruct_chain("token-B", db_session)
    assert chain == ["token-A", "token-B", "token-C"]

def test_interleaved_independent_families(db_session):
    # Family 1 Root (A) and Family 2 Root (X)
    process_event({"event_id": "e1", "event_type": "token_issued", "time": "12:00", "user_id": "u1", "token_hash": "token-A", "token_family": "fam-1", "ip_hash": "ip", "device_id": "d", "result": "accepted"}, db_session)
    process_event({"event_id": "e2", "event_type": "token_issued", "time": "12:01", "user_id": "u2", "token_hash": "token-X", "token_family": "fam-2", "ip_hash": "ip", "device_id": "d", "result": "accepted"}, db_session)
    
    # Interleaved rotates
    process_event({"event_id": "e3", "event_type": "token_refreshed", "time": "12:05", "user_id": "u1", "token_hash": "token-B", "parent_token_hash": "token-A", "ip_hash": "ip", "device_id": "d", "result": "accepted"}, db_session)
    process_event({"event_id": "e4", "event_type": "token_refreshed", "time": "12:06", "user_id": "u2", "token_hash": "token-Y", "parent_token_hash": "token-X", "ip_hash": "ip", "device_id": "d", "result": "accepted"}, db_session)

    b = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == "token-B").first()
    y = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == "token-Y").first()

    assert b.token_family == "fam-1"
    assert y.token_family == "fam-2"

    assert reconstruct_chain("token-B", db_session) == ["token-A", "token-B"]
    assert reconstruct_chain("token-Y", db_session) == ["token-X", "token-Y"]

def test_refresh_token_reuse_detection(db_session):
    # Issue and rotate A -> B
    process_event({"event_id": "e1", "event_type": "token_issued", "time": "12:00", "user_id": "u1", "token_hash": "token-A", "token_family": "fam-1", "ip_hash": "ip", "device_id": "d", "result": "accepted"}, db_session)
    process_event({"event_id": "e2", "event_type": "token_refreshed", "time": "12:05", "user_id": "u1", "token_hash": "token-B", "parent_token_hash": "token-A", "ip_hash": "ip", "device_id": "d", "result": "accepted"}, db_session)

    # Replay A to get B2 (reuse attempt)
    process_event({"event_id": "e3-replay", "event_type": "token_refreshed", "time": "12:10", "user_id": "u1", "token_hash": "token-B2", "parent_token_hash": "token-A", "ip_hash": "ip-attacker", "device_id": "d-attacker", "result": "rejected"}, db_session)

    # Assert reuse is recorded
    reuse_records = db_session.query(TokenReuseRecord).all()
    assert len(reuse_records) == 1
    assert reuse_records[0].token_hash == "token-A"
    assert reuse_records[0].attempted_event_id == "e3-replay"
    assert reuse_records[0].token_family == "fam-1"

def test_missing_parent_graceful_handling(db_session):
    # Rotate with missing parent event
    process_event({
        "event_id": "evt-missing-parent",
        "event_type": "token_refreshed",
        "time": "2026-08-16T12:00:00Z",
        "user_id": "user-1",
        "token_hash": "token-child",
        "parent_token_hash": "token-parent-unseen",
        "token_family": "fam-unseen",
        "ip_hash": "ip-1",
        "device_id": "dev-1",
        "result": "accepted"
    }, db_session)

    parent = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == "token-parent-unseen").first()
    child = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == "token-child").first()

    assert parent is not None
    assert parent.is_rotated is True
    assert parent.superseded_by == "token-child"
    assert child is not None
    assert child.parent_token_hash == "token-parent-unseen"
    assert child.token_family == parent.token_family

def test_khushi_synthetic_dataset_processing(db_session):
    # Load dataset
    dataset_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "synthetic", "refresh-reuse.json")
    with open(dataset_path, "r") as f:
        events = json.load(f)

    # Feed events
    for event in events:
        process_event(event, db_session)

    parent = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == "hash_8f8a7544c420").first()
    child = db_session.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == "hash_2358bd5b54a9").first()

    assert parent is not None
    assert parent.is_rotated is True
    assert parent.token_family == "family-refresh-42"

    assert child is not None
    assert child.token_family == "family-refresh-42"
    assert child.parent_token_hash == "hash_8f8a7544c420"

    # Verify reconstruction
    chain = reconstruct_chain("hash_2358bd5b54a9", db_session)
    assert chain == ["hash_8f8a7544c420", "hash_2358bd5b54a9"]

    # Verify that the reuse of rotated token 'hash_8f8a7544c420' was flagged/recorded
    reuse_records = db_session.query(TokenReuseRecord).filter(TokenReuseRecord.token_hash == "hash_8f8a7544c420").all()
    assert len(reuse_records) == 1
    assert reuse_records[0].token_family == "family-refresh-42"
    assert reuse_records[0].attempted_event_id == "evt-reuse-005"


def test_db_idempotent_event_replay_100_times(db_session):
    issue_event = {
        "event_id": "e-db-iss",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-db",
        "token_hash": "tok-db-A",
        "token_family": "fam-db-idem",
        "ip_hash": "ip1",
        "device_id": "dev1",
        "result": "accepted"
    }
    rot_event = {
        "event_id": "e-db-rot",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:10:00Z",
        "user_id": "u-db",
        "token_hash": "tok-db-B",
        "parent_token_hash": "tok-db-A",
        "ip_hash": "ip1",
        "device_id": "dev1",
        "result": "accepted"
    }

    # Process issuance and rotation multiple times (replays)
    for _ in range(10):
        process_event(issue_event, db_session)
        process_event(rot_event, db_session)

    # Assert no false reuse records in DB
    reuse_records = db_session.query(TokenReuseRecord).all()
    assert len(reuse_records) == 0

    # Attack event
    attack_event_1 = {
        "event_id": "e-db-atk-1",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:20:00Z",
        "user_id": "u-db",
        "token_hash": "tok-db-B-fake",
        "parent_token_hash": "tok-db-A",
        "ip_hash": "ip-bad",
        "device_id": "dev-bad",
        "result": "rejected"
    }

    # Replay attack 100 times in DB
    for _ in range(100):
        process_event(attack_event_1, db_session)

    # Uniqueness constraint & logic must ensure exactly 1 record in DB
    reuse_records = db_session.query(TokenReuseRecord).all()
    assert len(reuse_records) == 1
    assert reuse_records[0].attempted_event_id == "e-db-atk-1"
    assert reuse_records[0].token_hash == "tok-db-A"

    # Distinct attack event with same token
    attack_event_2 = {
        "event_id": "e-db-atk-2",
        "event_type": "token_used",
        "time": "2026-09-01T10:30:00Z",
        "user_id": "u-db",
        "token_hash": "tok-db-A",
        "ip_hash": "ip-bad-2",
        "device_id": "dev-bad-2",
        "result": "rejected"
    }
    for _ in range(50):
        process_event(attack_event_2, db_session)

    # Distinct event must produce a separate record -> exactly 2 records total
    reuse_records = db_session.query(TokenReuseRecord).all()
    assert len(reuse_records) == 2
    assert {r.attempted_event_id for r in reuse_records} == {"e-db-atk-1", "e-db-atk-2"}

