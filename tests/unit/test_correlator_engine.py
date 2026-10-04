import os
import sys
import pytest

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
    assert correlator.tokens["tok-logout-test"].metadata.get("revoked_at") == "2026-09-01T10:20:00Z"


def test_token_expired_and_revoked_events(correlator):
    # Issue tokens
    correlator.process_event({
        "event_id": "ev-iss-1",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "user-exp",
        "token_hash": "tok-exp-1",
        "token_family": "fam-exp",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })
    correlator.process_event({
        "event_id": "ev-iss-2",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "user-rev",
        "token_hash": "tok-rev-1",
        "token_family": "fam-rev",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })

    assert correlator.tokens["tok-exp-1"].status == TokenStatus.ACTIVE
    assert correlator.tokens["tok-rev-1"].status == TokenStatus.ACTIVE

    # Trigger token_expired
    correlator.process_event({
        "event_id": "ev-exp",
        "event_type": "token_expired",
        "time": "2026-09-01T11:00:00Z",
        "user_id": "user-exp",
        "token_hash": "tok-exp-1",
        "token_family": "fam-exp",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "rejected"
    })
    assert correlator.tokens["tok-exp-1"].status == TokenStatus.EXPIRED

    # Trigger token_revoked
    correlator.process_event({
        "event_id": "ev-rev",
        "event_type": "token_revoked",
        "time": "2026-09-01T11:15:00Z",
        "user_id": "user-rev",
        "token_hash": "tok-rev-1",
        "token_family": "fam-rev",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "rejected"
    })
    assert correlator.tokens["tok-rev-1"].status == TokenStatus.REVOKED
    assert correlator.tokens["tok-rev-1"].metadata.get("revoked_at") == "2026-09-01T11:15:00Z"


def test_idempotent_event_replay_single_reuse_record(correlator):
    # 1. Issue Token A
    correlator.process_event({
        "event_id": "e-issue",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u1",
        "token_hash": "tok-A",
        "token_family": "fam-idem",
        "ip_hash": "ip1",
        "device_id": "dev1",
        "result": "accepted"
    })

    # 2. Legitimate rotation Token A -> Token B
    rot_event = {
        "event_id": "e-rotate-1",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:10:00Z",
        "user_id": "u1",
        "token_hash": "tok-B",
        "parent_token_hash": "tok-A",
        "ip_hash": "ip1",
        "device_id": "dev1",
        "result": "accepted"
    }
    correlator.process_event(rot_event)

    # 3. Replay legitimate rotation 100 times -> MUST NOT produce any reuse alerts (false positives)
    for _ in range(100):
        correlator.process_event(rot_event)
    assert len(correlator.get_reuse_records()) == 0

    # 4. Attack event: presentation of rotated Token A with event_id 'e-attack-1'
    attack_event_1 = {
        "event_id": "e-attack-1",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:20:00Z",
        "user_id": "u1",
        "token_hash": "tok-B-evil",
        "parent_token_hash": "tok-A",
        "ip_hash": "ip-evil",
        "device_id": "dev-evil",
        "result": "rejected"
    }

    # Process once
    r1 = correlator.process_event(attack_event_1)
    assert r1 is not None
    assert len(correlator.get_reuse_records()) == 1

    # Process the exact same event 100 times -> MUST still have exactly 1 reuse record
    for _ in range(100):
        correlator.process_event(attack_event_1)
    assert len(correlator.get_reuse_records()) == 1
    assert correlator.get_reuse_records()[0].attempted_event_id == "e-attack-1"

    # 5. Different attack event using the same rotated token (different event_id 'e-attack-2')
    attack_event_2 = {
        "event_id": "e-attack-2",
        "event_type": "token_used",
        "time": "2026-09-01T10:30:00Z",
        "user_id": "u1",
        "token_hash": "tok-A",
        "ip_hash": "ip-evil-2",
        "device_id": "dev-evil-2",
        "result": "rejected"
    }
    r2 = correlator.process_event(attack_event_2)
    assert r2 is not None

    # Replay attack_event_2 50 times -> MUST result in exactly 2 distinct reuse records
    for _ in range(50):
        correlator.process_event(attack_event_2)
    records = correlator.get_reuse_records()
    assert len(records) == 2
    assert {r.attempted_event_id for r in records} == {"e-attack-1", "e-attack-2"}


def test_logout_revokes_entire_family_and_preserves_lineage(correlator):
    # 1. Issue Token A (root)
    correlator.process_event({
        "event_id": "e-iss",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-alice",
        "token_hash": "tok-fam-A",
        "token_family": "fam-alice-1",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })

    # 2. Refresh Token A -> Token B
    correlator.process_event({
        "event_id": "e-rot-1",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:10:00Z",
        "user_id": "u-alice",
        "token_hash": "tok-fam-B",
        "parent_token_hash": "tok-fam-A",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })

    # 3. Refresh Token B -> Token C
    correlator.process_event({
        "event_id": "e-rot-2",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:20:00Z",
        "user_id": "u-alice",
        "token_hash": "tok-fam-C",
        "parent_token_hash": "tok-fam-B",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })

    assert correlator.tokens["tok-fam-A"].status == TokenStatus.ROTATED
    assert correlator.tokens["tok-fam-B"].status == TokenStatus.ROTATED
    assert correlator.tokens["tok-fam-C"].status == TokenStatus.ACTIVE

    # Lineage before logout
    assert correlator.reconstruct_chain("tok-fam-C") == ["tok-fam-A", "tok-fam-B", "tok-fam-C"]
    assert correlator.get_ancestors("tok-fam-C") == ["tok-fam-A", "tok-fam-B"]
    assert correlator.get_descendants("tok-fam-A") == ["tok-fam-B", "tok-fam-C"]

    # 4. User logs out presenting the active token tok-fam-C
    correlator.process_event({
        "event_id": "e-logout",
        "event_type": "logout",
        "time": "2026-09-01T10:30:00Z",
        "user_id": "u-alice",
        "token_hash": "tok-fam-C",
        "token_family": "fam-alice-1",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })

    # Acceptance Criteria: Logout revokes the relevant family
    assert correlator.tokens["tok-fam-A"].status == TokenStatus.REVOKED
    assert correlator.tokens["tok-fam-B"].status == TokenStatus.REVOKED
    assert correlator.tokens["tok-fam-C"].status == TokenStatus.REVOKED

    # Acceptance Criteria: Revoked tokens cannot remain active
    for tok_hash in ["tok-fam-A", "tok-fam-B", "tok-fam-C"]:
        assert correlator.tokens[tok_hash].status != TokenStatus.ACTIVE
        assert correlator.tokens[tok_hash].metadata.get("revoked_at") == "2026-09-01T10:30:00Z"

    # Acceptance Criteria: Descendant/ancestor relationships remain correct
    assert correlator.reconstruct_chain("tok-fam-C") == ["tok-fam-A", "tok-fam-B", "tok-fam-C"]
    assert correlator.get_ancestors("tok-fam-C") == ["tok-fam-A", "tok-fam-B"]
    assert correlator.get_descendants("tok-fam-A") == ["tok-fam-B", "tok-fam-C"]


def test_revoked_tokens_cannot_transition_to_active(correlator):
    # 1. Issue and revoke token
    correlator.process_event({
        "event_id": "e-iss",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-bob",
        "token_hash": "tok-bob-1",
        "token_family": "fam-bob-1",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })
    correlator.process_event({
        "event_id": "e-rev",
        "event_type": "token_revoked",
        "time": "2026-09-01T10:05:00Z",
        "user_id": "u-bob",
        "token_hash": "tok-bob-1",
        "token_family": "fam-bob-1",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })
    assert correlator.tokens["tok-bob-1"].status == TokenStatus.REVOKED

    # 2. Subsequent issuance event with the same token_hash must NOT make it active again
    correlator.process_event({
        "event_id": "e-iss-replayed",
        "event_type": "token_issued",
        "time": "2026-09-01T10:10:00Z",
        "user_id": "u-bob",
        "token_hash": "tok-bob-1",
        "token_family": "fam-bob-1",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted"
    })
    assert correlator.tokens["tok-bob-1"].status == TokenStatus.REVOKED
    assert correlator.tokens["tok-bob-1"].status != TokenStatus.ACTIVE


def test_correlator_engine_db_sync_error_handling(correlator, caplog):
    import logging
    from unittest.mock import MagicMock

    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.first.return_value = None
    mock_session.commit.side_effect = RuntimeError("Database disk failure during sync")

    event = {
        "event_id": "e-fail-sync",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-sync",
        "token_hash": "tok-sync-1",
        "token_family": "fam-sync-1",
        "ip_hash": "ip-sync",
        "device_id": "dev-sync",
        "result": "accepted"
    }

    with caplog.at_level(logging.ERROR, logger="tokenline.correlator.engine"):
        with pytest.raises(RuntimeError, match="Database disk failure during sync"):
            correlator.process_event(event, db_session=mock_session)

    # Verify rollback was called and error was logged (no silent except: pass)
    mock_session.rollback.assert_called()
    assert "Database synchronization failed during correlation for event e-fail-sync" in caplog.text
    assert "Database disk failure during sync" in caplog.text





