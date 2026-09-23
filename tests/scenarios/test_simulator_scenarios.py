import os
import sys
import json
import pytest

# Ensure repository root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from simulator.runner import run_scenario, run_all_scenarios, CANONICAL_SCENARIO_NAMES
from simulator.base import EVENT_SCHEMA
from backend.correlator import TokenFamilyCorrelator, TokenStatus
import jsonschema


@pytest.mark.parametrize("scenario_name", CANONICAL_SCENARIO_NAMES)
def test_scenario_schema_compliance(scenario_name):
    events = run_scenario(scenario_name, seed=123)
    assert len(events) >= 3
    assert EVENT_SCHEMA is not None

    for evt in events:
        # Strict validation against schema/event.schema.json
        jsonschema.validate(instance=evt, schema=EVENT_SCHEMA)
        assert "event_id" in evt
        assert "event_type" in evt
        assert "time" in evt
        assert "user_id" in evt
        assert "token_hash" in evt
        assert "ip_hash" in evt
        assert "device_id" in evt
        assert "result" in evt
        assert evt["result"] in ["accepted", "rejected"]


def test_scenario_deterministic_reproducibility():
    for name in CANONICAL_SCENARIO_NAMES:
        run_1 = run_scenario(name, seed=42)
        run_2 = run_scenario(name, seed=42)
        assert run_1 == run_2, f"Scenario '{name}' output is not deterministic across runs with the same seed"

        # Different seed should generate different tokens
        run_3 = run_scenario(name, seed=999)
        assert run_1 != run_3, f"Scenario '{name}' generated identical events for different seeds"


def test_run_all_scenarios():
    results = run_all_scenarios(seed=42)
    assert set(results.keys()) == set(CANONICAL_SCENARIO_NAMES)
    total_events = sum(len(evts) for evts in results.values())
    assert total_events >= 19


def test_correlator_detects_refresh_reuse_scenario():
    events = run_scenario("refresh-reuse", seed=42)
    correlator = TokenFamilyCorrelator()

    for evt in events:
        correlator.process_event(evt)

    # Verify correlator state
    reuse_records = correlator.get_reuse_records()
    assert len(reuse_records) == 1
    reused = reuse_records[0]
    assert reused.attempted_event_id == "evt-reuse-005"
    assert "token-root-A" in reused.token_hash or "hash_" in reused.token_hash


def test_correlator_processes_revoked_token_scenario():
    events = run_scenario("revoked-token", seed=42)
    correlator = TokenFamilyCorrelator()

    for evt in events:
        correlator.process_event(evt)

    token_hash = events[0]["token_hash"]
    record = correlator.tokens.get(token_hash)
    assert record is not None
    assert record.status == TokenStatus.REVOKED


def test_concurrent_use_scenario_structure():
    events = run_scenario("concurrent-use", seed=42)
    device_ids = [e["device_id"] for e in events]
    assert "device-workstation-office" in device_ids
    assert "device-rogue-clone" in device_ids


def test_impossible_travel_scenario_structure():
    events = run_scenario("impossible-travel", seed=42)
    countries = [e.get("country") for e in events if "country" in e]
    assert "IN" in countries
    assert "US" in countries
