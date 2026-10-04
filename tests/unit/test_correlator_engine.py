import os
import sys
import json
import pytest
import jsonschema
import logging

# Ensure repository root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.correlator import TokenFamilyCorrelator, TokenStatus, TokenRecord, TokenReuseRecord
from simulator.base import EVENT_SCHEMA


@pytest.fixture
def correlator():
    return TokenFamilyCorrelator()


def make_schema_valid_event(
    event_id: str,
    event_type: str,
    time: str,
    user_id: str,
    token_hash: str,
    token_family: str,
    parent_token_hash: str = None,
    result: str = "accepted",
    device_id: str = "device-workstation",
    ip_hash: str = "ip-test-hash",
    country: str = "US",
    endpoint: str = "/api/v1/resource",
) -> dict:
    """Helper creating a strictly schema-valid event payload conforming to schema/event.schema.json."""
    evt = {
        "event_id": event_id,
        "event_type": event_type,
        "time": time,
        "user_id": user_id,
        "token_hash": token_hash,
        "token_family": token_family,
        "ip_hash": ip_hash,
        "country": country,
        "device_id": device_id,
        "user_agent_family": "Chrome",
        "endpoint": endpoint,
        "result": result,
    }
    if parent_token_hash:
        evt["parent_token_hash"] = parent_token_hash
    if EVENT_SCHEMA:
        jsonschema.validate(instance=evt, schema=EVENT_SCHEMA)
    return evt


# =========================================================================
# ISSUE #11 SPECIFIED TESTS (TEST 1 - TEST 7)
# =========================================================================

def test_1_normal_rotation(correlator):
    """
    TEST 1 — Normal rotation
    Input: A -> B -> C
    Expected: A -> B -> C, all belong to the same token family.
    """
    e1 = make_schema_valid_event("e1", "token_issued", "2026-09-01T10:00:00Z", "alice", "tok-A", "family-1")
    e2 = make_schema_valid_event("e2", "token_refreshed", "2026-09-01T10:15:00Z", "alice", "tok-B", "family-1", parent_token_hash="tok-A")
    e3 = make_schema_valid_event("e3", "token_refreshed", "2026-09-01T10:30:00Z", "alice", "tok-C", "family-1", parent_token_hash="tok-B")

    correlator.process_event(e1)
    correlator.process_event(e2)
    correlator.process_event(e3)

    chain = correlator.reconstruct_chain("tok-A")
    assert chain == ["tok-A", "tok-B", "tok-C"]

    # Verify all belong to the same family
    for t_hash in ["tok-A", "tok-B", "tok-C"]:
        assert correlator.tokens[t_hash].token_family == "family-1"


def test_2_parent_child_relationship(correlator):
    """
    TEST 2 — Parent/child relationship
    Verify:
    B.parent_token_hash == A
    C.parent_token_hash == B
    """
    e1 = make_schema_valid_event("e1", "token_issued", "2026-09-01T10:00:00Z", "alice", "tok-A", "family-1")
    e2 = make_schema_valid_event("e2", "token_refreshed", "2026-09-01T10:15:00Z", "alice", "tok-B", "family-1", parent_token_hash="tok-A")
    e3 = make_schema_valid_event("e3", "token_refreshed", "2026-09-01T10:30:00Z", "alice", "tok-C", "family-1", parent_token_hash="tok-B")

    correlator.process_event(e1)
    correlator.process_event(e2)
    correlator.process_event(e3)

    assert correlator.tokens["tok-A"].parent_token_hash is None
    assert correlator.tokens["tok-B"].parent_token_hash == "tok-A"
    assert correlator.tokens["tok-C"].parent_token_hash == "tok-B"


def test_3_token_family_propagation(correlator):
    """
    TEST 3 — Token family propagation
    Verify:
    A.token_family == B.token_family == C.token_family
    """
    e1 = make_schema_valid_event("e1", "token_issued", "2026-09-01T10:00:00Z", "alice", "tok-A", "family-propagation-test")
    # For e2 and e3, do not explicitly pass token_family to prove it propagates from parent
    e2 = make_schema_valid_event("e2", "token_refreshed", "2026-09-01T10:15:00Z", "alice", "tok-B", "family-propagation-test", parent_token_hash="tok-A")
    e3 = make_schema_valid_event("e3", "token_refreshed", "2026-09-01T10:30:00Z", "alice", "tok-C", "family-propagation-test", parent_token_hash="tok-B")

    correlator.process_event(e1)
    correlator.process_event(e2)
    correlator.process_event(e3)

    assert (
        correlator.tokens["tok-A"].token_family
        == correlator.tokens["tok-B"].token_family
        == correlator.tokens["tok-C"].token_family
        == "family-propagation-test"
    )


def test_4_multiple_independent_families(correlator):
    """
    TEST 4 — Multiple independent families
    Input:
    Family 1: A -> B -> C
    Family 2: X -> Y -> Z
    Expected:
    Family 1: A -> B -> C
    Family 2: X -> Y -> Z
    No cross-family relationships.
    """
    # Family 1
    correlator.process_event(make_schema_valid_event("f1-1", "token_issued", "2026-09-01T10:00:00Z", "user1", "tok-A", "family-1"))
    correlator.process_event(make_schema_valid_event("f1-2", "token_refreshed", "2026-09-01T10:10:00Z", "user1", "tok-B", "family-1", parent_token_hash="tok-A"))
    correlator.process_event(make_schema_valid_event("f1-3", "token_refreshed", "2026-09-01T10:20:00Z", "user1", "tok-C", "family-1", parent_token_hash="tok-B"))

    # Family 2 (interleaved in time)
    correlator.process_event(make_schema_valid_event("f2-1", "token_issued", "2026-09-01T10:05:00Z", "user2", "tok-X", "family-2"))
    correlator.process_event(make_schema_valid_event("f2-2", "token_refreshed", "2026-09-01T10:15:00Z", "user2", "tok-Y", "family-2", parent_token_hash="tok-X"))
    correlator.process_event(make_schema_valid_event("f2-3", "token_refreshed", "2026-09-01T10:25:00Z", "user2", "tok-Z", "family-2", parent_token_hash="tok-Y"))

    # Verify chains are independent
    assert correlator.reconstruct_chain("tok-A") == ["tok-A", "tok-B", "tok-C"]
    assert correlator.reconstruct_chain("tok-X") == ["tok-X", "tok-Y", "tok-Z"]

    # Verify no cross-family leakage in family lookups
    fam1_tokens = [t.token_hash for t in correlator.get_family("family-1")]
    fam2_tokens = [t.token_hash for t in correlator.get_family("family-2")]

    assert set(fam1_tokens) == {"tok-A", "tok-B", "tok-C"}
    assert set(fam2_tokens) == {"tok-X", "tok-Y", "tok-Z"}
    assert set(fam1_tokens).isdisjoint(set(fam2_tokens))


def test_5_refresh_token_reuse(correlator):
    """
    TEST 5 — Refresh-token reuse
    Input:
    A -> B
    Then A is used for refresh again.
    Expected:
    - A is recognized as already rotated
    - reuse condition is recorded
    - A remains associated with the correct family
    - B remains the legitimate child of A
    """
    # 1. Issue A
    correlator.process_event(make_schema_valid_event("e1", "token_issued", "2026-09-01T12:00:00Z", "bob", "tok-A", "family-bob"))
    # 2. Legitimate rotate A -> B
    correlator.process_event(make_schema_valid_event("e2", "token_refreshed", "2026-09-01T12:10:00Z", "bob", "tok-B", "family-bob", parent_token_hash="tok-A"))

    # 3. Attacker presents rotated token A again
    reuse_event = make_schema_valid_event(
        "e3-attacker-reuse",
        "token_refreshed",
        "2026-09-01T12:15:00Z",
        "bob",
        "tok-C-attacker",
        "family-bob",
        parent_token_hash="tok-A",
        result="rejected",
        device_id="device-attacker-box"
    )
    detected_reuse = correlator.process_event(reuse_event)

    # A is recognized as already rotated
    assert correlator.tokens["tok-A"].is_rotated is True
    assert correlator.tokens["tok-A"].status == TokenStatus.ROTATED

    # Reuse condition is recorded
    assert detected_reuse is not None
    assert detected_reuse.token_hash == "tok-A"
    assert detected_reuse.token_family == "family-bob"
    assert detected_reuse.attempted_event_id == "e3-attacker-reuse"
    assert len(correlator.get_reuse_records(token_family="family-bob")) == 1

    # A remains associated with the correct family
    assert correlator.tokens["tok-A"].token_family == "family-bob"

    # B remains the legitimate child of A (chain does NOT replace B with attacker token C)
    assert correlator.tokens["tok-A"].superseded_by == "tok-B"
    assert correlator.tokens["tok-B"].parent_token_hash == "tok-A"
    assert correlator.reconstruct_chain("tok-A") == ["tok-A", "tok-B"]


def test_6_long_refresh_chain(correlator):
    """
    TEST 6 — Long refresh chain
    Test: A -> B -> C -> D
    Verify the complete chain can be reconstructed.
    """
    tokens = ["tok-node-A", "tok-node-B", "tok-node-C", "tok-node-D"]
    correlator.process_event(make_schema_valid_event("ev-0", "token_issued", "2026-09-01T10:00:00Z", "u", tokens[0], "fam-long"))

    for i in range(1, len(tokens)):
        correlator.process_event(make_schema_valid_event(
            f"ev-{i}",
            "token_refreshed",
            f"2026-09-01T10:{i*10:02d}:00Z",
            "u",
            tokens[i],
            "fam-long",
            parent_token_hash=tokens[i - 1]
        ))

    # Verify reconstruction from any point in the chain
    for t in tokens:
        assert correlator.reconstruct_chain(t) == tokens

    # Also from the family identifier itself
    assert correlator.reconstruct_chain("fam-long") == tokens


def test_7_schema_compatibility():
    """
    TEST 7 — Schema compatibility
    Verify that test events conform strictly to schema/event.schema.json.
    """
    assert EVENT_SCHEMA is not None, "event.schema.json could not be loaded"

    sample_events = [
        make_schema_valid_event("s1", "token_issued", "2026-09-01T10:00:00Z", "u", "tok-1", "fam-1"),
        make_schema_valid_event("s2", "token_used", "2026-09-01T10:05:00Z", "u", "tok-1", "fam-1"),
        make_schema_valid_event("s3", "token_refreshed", "2026-09-01T10:10:00Z", "u", "tok-2", "fam-1", parent_token_hash="tok-1"),
        make_schema_valid_event("s4", "logout", "2026-09-01T10:20:00Z", "u", "tok-2", "fam-1"),
    ]

    for evt in sample_events:
        jsonschema.validate(instance=evt, schema=EVENT_SCHEMA)


# =========================================================================
# SYNTHETIC DATASET INTEGRATION TESTS (ISSUE #8 DATASETS)
# =========================================================================

def test_synthetic_dataset_normal_processing(correlator):
    """Verifies that the correlator processes the Issue #8 normal.json dataset correctly."""
    dataset_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "synthetic", "normal.json")
    with open(dataset_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    for evt in events:
        correlator.process_event(evt)

    # In normal.json: token A is issued and rotated to token B
    root_hash = events[0]["token_hash"]
    child_hash = events[3]["token_hash"]
    assert correlator.tokens[root_hash].status == TokenStatus.ROTATED
    assert correlator.tokens[child_hash].status == TokenStatus.REVOKED  # Concluded with logout
    assert correlator.reconstruct_chain(root_hash) == [root_hash, child_hash]
    assert len(correlator.get_reuse_records()) == 0


def test_synthetic_dataset_refresh_reuse_processing(correlator):
    """Verifies that the correlator processes the Issue #8 refresh-reuse.json dataset correctly."""
    dataset_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "synthetic", "refresh-reuse.json")
    with open(dataset_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    for evt in events:
        correlator.process_event(evt)

    # 1 reuse record must be flagged for the reuse event (evt-reuse-005)
    reuse_records = correlator.get_reuse_records()
    assert len(reuse_records) == 1
    assert reuse_records[0].attempted_event_id == "evt-reuse-005"
    assert reuse_records[0].token_hash == events[0]["token_hash"]


# =========================================================================
# ANCESTOR, DESCENDANT & REVOCATION HELPER TESTS
# =========================================================================

def test_ancestor_and_descendant_lookups(correlator):
    chain_nodes = ["n1", "n2", "n3", "n4"]
    correlator.process_event(make_schema_valid_event("e1", "token_issued", "2026-09-01T10:00:00Z", "u", "n1", "fam-tree"))
    for i in range(1, 4):
        correlator.process_event(make_schema_valid_event(
            f"e{i+1}",
            "token_refreshed",
            f"2026-09-01T10:{i*10:02d}:00Z",
            "u",
            chain_nodes[i],
            "fam-tree",
            parent_token_hash=chain_nodes[i - 1]
        ))

    assert correlator.get_ancestors("n1") == []
    assert correlator.get_ancestors("n2") == ["n1"]
    assert correlator.get_ancestors("n4") == ["n1", "n2", "n3"]

    assert correlator.get_descendants("n1") == ["n2", "n3", "n4"]
    assert correlator.get_descendants("n3") == ["n4"]
    assert correlator.get_descendants("n4") == []


def test_logout_and_revocation_status(correlator):
    correlator.process_event(make_schema_valid_event("ev-login", "token_issued", "2026-09-01T10:00:00Z", "u", "tok-rev", "fam-rev"))
    assert correlator.tokens["tok-rev"].status == TokenStatus.ACTIVE

    correlator.process_event(make_schema_valid_event("ev-logout", "logout", "2026-09-01T10:20:00Z", "u", "tok-rev", "fam-rev"))
    assert correlator.tokens["tok-rev"].status == TokenStatus.REVOKED


def test_correlator_engine_db_sync_error_handling(caplog):
    """
    _sync_with_db must not silently pass; it must rollback session, log, and raise.
    """
    correlator = TokenFamilyCorrelator()

    class FaultyDBSession:
        def query(self, *args, **kwargs):
            raise RuntimeError("Database connection lost during correlation sync")
        def rollback(self):
            self.rolled_back = True

    faulty_session = FaultyDBSession()
    event_data = {
        "event_id": "evt-faulty-sync",
        "event_type": "token_refreshed",
        "time": "2026-08-16T10:00:00Z",
        "token_hash": "child_hash",
        "parent_token_hash": "parent_hash"
    }

    with caplog.at_level(logging.ERROR):
        with pytest.raises(RuntimeError, match="Database connection lost"):
            correlator.process_event(event_data, db_session=faulty_session)

    assert faulty_session.rolled_back is True
    assert any("Database synchronization failed during correlation" in record.message for record in caplog.records)
