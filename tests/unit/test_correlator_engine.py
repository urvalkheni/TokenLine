import os
import sys
import pytest

# Ensure repository root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.correlator import TokenFamilyCorrelator, TokenStatus, TokenRecord, TokenReuseRecord


@pytest.fixture
def correlator():
    return TokenFamilyCorrelator()


def test_normal_three_token_rotation(correlator):
    # 1. Issue Token A
    correlator.process_event({
        "event_id": "evt-1",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "user-alice",
        "token_hash": "token-hash-A",
        "token_family": "family-alpha",
        "ip_hash": "ip-home-1",
        "device_id": "device-macbook",
        "result": "accepted"
    })

    # 2. Refresh Token A -> Token B
    correlator.process_event({
        "event_id": "evt-2",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:30:00Z",
        "user_id": "user-alice",
        "token_hash": "token-hash-B",
        "parent_token_hash": "token-hash-A",
        "ip_hash": "ip-home-1",
        "device_id": "device-macbook",
        "result": "accepted"
    })

    # 3. Refresh Token B -> Token C
    correlator.process_event({
        "event_id": "evt-3",
        "event_type": "token_refreshed",
        "time": "2026-09-01T11:00:00Z",
        "user_id": "user-alice",
        "token_hash": "token-hash-C",
        "parent_token_hash": "token-hash-B",
        "ip_hash": "ip-home-1",
        "device_id": "device-macbook",
        "result": "accepted"
    })

    # Assert tokens status and family propagation
    rec_a = correlator.tokens.get("token-hash-A")
    rec_b = correlator.tokens.get("token-hash-B")
    rec_c = correlator.tokens.get("token-hash-C")

    assert rec_a is not None and rec_a.status == TokenStatus.ROTATED
    assert rec_b is not None and rec_b.status == TokenStatus.ROTATED
    assert rec_c is not None and rec_c.status == TokenStatus.ACTIVE

    assert rec_a.token_family == "family-alpha"
    assert rec_b.token_family == "family-alpha"
    assert rec_c.token_family == "family-alpha"

    # Reconstruct chain from any node
    assert correlator.reconstruct_chain("token-hash-A") == ["token-hash-A", "token-hash-B", "token-hash-C"]
    assert correlator.reconstruct_chain("token-hash-B") == ["token-hash-A", "token-hash-B", "token-hash-C"]
    assert correlator.reconstruct_chain("token-hash-C") == ["token-hash-A", "token-hash-B", "token-hash-C"]
    assert correlator.reconstruct_chain("family-alpha") == ["token-hash-A", "token-hash-B", "token-hash-C"]


def test_independent_families_do_not_cross_contaminate(correlator):
    # Family 1: A -> B
    correlator.process_event({
        "event_id": "f1-1",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "user-1",
        "token_hash": "token-F1-A",
        "token_family": "family-1",
        "ip_hash": "ip-1",
        "device_id": "dev-1",
        "result": "accepted"
    })
    correlator.process_event({
        "event_id": "f1-2",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:15:00Z",
        "user_id": "user-1",
        "token_hash": "token-F1-B",
        "parent_token_hash": "token-F1-A",
        "ip_hash": "ip-1",
        "device_id": "dev-1",
        "result": "accepted"
    })

    # Family 2: X -> Y -> Z
    correlator.process_event({
        "event_id": "f2-1",
        "event_type": "token_issued",
        "time": "2026-09-01T10:05:00Z",
        "user_id": "user-2",
        "token_hash": "token-F2-X",
        "token_family": "family-2",
        "ip_hash": "ip-2",
        "device_id": "dev-2",
        "result": "accepted"
    })
    correlator.process_event({
        "event_id": "f2-2",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:20:00Z",
        "user_id": "user-2",
        "token_hash": "token-F2-Y",
        "parent_token_hash": "token-F2-X",
        "ip_hash": "ip-2",
        "device_id": "dev-2",
        "result": "accepted"
    })
    correlator.process_event({
        "event_id": "f2-3",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:35:00Z",
        "user_id": "user-2",
        "token_hash": "token-F2-Z",
        "parent_token_hash": "token-F2-Y",
        "ip_hash": "ip-2",
        "device_id": "dev-2",
        "result": "accepted"
    })

    # Assert chains are independent
    assert correlator.reconstruct_chain("token-F1-B") == ["token-F1-A", "token-F1-B"]
    assert correlator.reconstruct_chain("token-F2-Z") == ["token-F2-X", "token-F2-Y", "token-F2-Z"]

    family1_tokens = correlator.get_family("family-1")
    family2_tokens = correlator.get_family("family-2")

    assert [t.token_hash for t in family1_tokens] == ["token-F1-A", "token-F1-B"]
    assert [t.token_hash for t in family2_tokens] == ["token-F2-X", "token-F2-Y", "token-F2-Z"]


def test_refresh_token_reuse_flagged(correlator):
    # Issue A and rotate to B
    correlator.process_event({
        "event_id": "e1",
        "event_type": "token_issued",
        "time": "2026-09-01T12:00:00Z",
        "user_id": "user-bob",
        "token_hash": "token-A",
        "token_family": "family-bob",
        "ip_hash": "ip-1",
        "device_id": "dev-1",
        "result": "accepted"
    })
    correlator.process_event({
        "event_id": "e2",
        "event_type": "token_refreshed",
        "time": "2026-09-01T12:10:00Z",
        "user_id": "user-bob",
        "token_hash": "token-B",
        "parent_token_hash": "token-A",
        "ip_hash": "ip-1",
        "device_id": "dev-1",
        "result": "accepted"
    })

    # Attacker attempts to refresh rotated token A again
    reuse_evt = {
        "event_id": "e3-attacker-reuse",
        "event_type": "token_refreshed",
        "time": "2026-09-01T12:15:00Z",
        "user_id": "user-bob",
        "token_hash": "token-B-attacker",
        "parent_token_hash": "token-A",
        "ip_hash": "ip-attacker",
        "device_id": "dev-attacker",
        "result": "rejected"
    }
    reuse_record = correlator.process_event(reuse_evt)

    assert reuse_record is not None
    assert reuse_record.token_hash == "token-A"
    assert reuse_record.token_family == "family-bob"
    assert reuse_record.reused_at == "2026-09-01T12:15:00Z"
    assert reuse_record.attempted_event_id == "e3-attacker-reuse"
    assert "token-A" in reuse_record.chain_context

    records = correlator.get_reuse_records(token_family="family-bob")
    assert len(records) == 1
    assert records[0].attempted_event_id == "e3-attacker-reuse"


def test_ancestor_and_descendant_lookups(correlator):
    # Create chain 1 -> 2 -> 3 -> 4
    correlator.process_event({
        "event_id": "ev-1",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "user-1",
        "token_hash": "t1",
        "token_family": "fam-num",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })
    for i in range(2, 5):
        correlator.process_event({
            "event_id": f"ev-{i}",
            "event_type": "token_refreshed",
            "time": f"2026-09-01T10:{i*10:02d}:00Z",
            "user_id": "user-1",
            "token_hash": f"t{i}",
            "parent_token_hash": f"t{i-1}",
            "ip_hash": "ip",
            "device_id": "dev",
            "result": "accepted"
        })

    # Ancestor lookups
    assert correlator.get_ancestors("t1") == []
    assert correlator.get_ancestors("t2") == ["t1"]
    assert correlator.get_ancestors("t4") == ["t1", "t2", "t3"]

    # Descendant lookups
    assert correlator.get_descendants("t1") == ["t2", "t3", "t4"]
    assert correlator.get_descendants("t3") == ["t4"]
    assert correlator.get_descendants("t4") == []


def test_logout_and_revocation_status(correlator):
    correlator.process_event({
        "event_id": "ev-login",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "user-1",
        "token_hash": "tok-logout-test",
        "token_family": "fam-logout",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })
    assert correlator.tokens["tok-logout-test"].status == TokenStatus.ACTIVE

    correlator.process_event({
        "event_id": "ev-logout",
        "event_type": "logout",
        "time": "2026-09-01T10:20:00Z",
        "user_id": "user-1",
        "token_hash": "tok-logout-test",
        "token_family": "fam-logout",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })
    assert correlator.tokens["tok-logout-test"].status == TokenStatus.REVOKED
