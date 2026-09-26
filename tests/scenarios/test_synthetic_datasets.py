import os
import sys
import json
import pytest
from datetime import datetime

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from simulator.dataset_generator import (
    generate_all_datasets,
    generate_scenario_dataset,
    DATASET_CONFIG,
    DATASET_SCENARIOS,
)
from simulator.base import EVENT_SCHEMA
from backend.correlator import TokenFamilyCorrelator, TokenStatus
import jsonschema


EXPECTED_FILENAMES = {
    "normal": "normal.json",
    "refresh-reuse": "refresh-reuse.json",
    "expired-token": "expired-token.json",
    "revoked-token": "revoked-token.json",
    "concurrent-use": "concurrent-use.json",
    "impossible-travel": "impossible-travel.json",
}


@pytest.fixture(scope="module")
def generated_datasets(tmp_path_factory):
    """Generates all 6 datasets in a temporary directory for test assertions."""
    temp_dir = tmp_path_factory.mktemp("synthetic_data")
    paths = generate_all_datasets(output_dir=str(temp_dir), seed=42)
    loaded = {}
    for sc_name, filepath in paths.items():
        with open(filepath, "r", encoding="utf-8") as f:
            loaded[sc_name] = {
                "path": filepath,
                "events": json.load(f),
            }
    return loaded


def test_all_six_datasets_generated(generated_datasets):
    """Verifies that all six required dataset files are created and contain valid JSON."""
    assert len(generated_datasets) == 6
    for sc_name, expected_file in EXPECTED_FILENAMES.items():
        assert sc_name in generated_datasets
        entry = generated_datasets[sc_name]
        assert os.path.basename(entry["path"]) == expected_file
        assert isinstance(entry["events"], list)
        assert len(entry["events"]) >= 3


@pytest.mark.parametrize("scenario_name", DATASET_SCENARIOS)
def test_every_event_conforms_to_schema(generated_datasets, scenario_name):
    """Strictly validates every single event across all scenarios against schema/event.schema.json."""
    assert EVENT_SCHEMA is not None, "Event schema could not be loaded"
    events = generated_datasets[scenario_name]["events"]

    for evt in events:
        # Schema validation
        jsonschema.validate(instance=evt, schema=EVENT_SCHEMA)

        # Explicit checks on required fields
        assert isinstance(evt["event_id"], str) and evt["event_id"]
        assert isinstance(evt["event_type"], str) and evt["event_type"]
        assert isinstance(evt["time"], str) and evt["time"]
        assert isinstance(evt["user_id"], str) and evt["user_id"]
        assert isinstance(evt["token_hash"], str) and evt["token_hash"]
        assert isinstance(evt["ip_hash"], str) and evt["ip_hash"]
        assert isinstance(evt["device_id"], str) and evt["device_id"]
        assert evt["result"] in ["accepted", "rejected"]

        # Validate country code format if present
        if "country" in evt:
            assert len(evt["country"]) == 2 and evt["country"].isupper()


def test_timestamps_valid_and_chronologically_ordered(generated_datasets):
    """Verifies that all event timestamps parse as ISO 8601 UTC and are strictly ordered."""
    for sc_name, data in generated_datasets.items():
        events = data["events"]
        parsed_times = []
        for evt in events:
            # Must parse as ISO-8601 UTC date-time
            t = datetime.strptime(evt["time"], "%Y-%m-%dT%H:%M:%SZ")
            parsed_times.append(t)

        # Check chronological ordering
        for i in range(len(parsed_times) - 1):
            assert parsed_times[i] <= parsed_times[i + 1], (
                f"Scenario '{sc_name}' has out-of-order timestamp at index {i}"
            )


def test_token_family_relationships_preserved(generated_datasets):
    """Verifies token and token-family lineage across all six scenarios."""
    # 1. Normal: Rotation link preserved from A to B within same family
    normal_events = generated_datasets["normal"]["events"]
    fam_normal = normal_events[0]["token_family"]
    assert fam_normal is not None
    token_a = normal_events[0]["token_hash"]
    refresh_event = [e for e in normal_events if e["event_type"] == "token_refreshed"][0]
    token_b = refresh_event["token_hash"]
    assert refresh_event["parent_token_hash"] == token_a
    assert refresh_event["token_family"] == fam_normal
    assert token_a != token_b

    # Subsequent events use token_b in the same family
    subsequent_normal = [e for e in normal_events if e["event_id"] in ["evt-normal-005", "evt-normal-006"]]
    for e in subsequent_normal:
        assert e["token_hash"] == token_b
        assert e["token_family"] == fam_normal

    # 2. Refresh Reuse: Both legitimate rotation and malicious reuse point to same parent token A
    reuse_events = generated_datasets["refresh-reuse"]["events"]
    fam_reuse = reuse_events[0]["token_family"]
    root_token = reuse_events[0]["token_hash"]
    refreshes = [e for e in reuse_events if e["event_type"] == "token_refreshed"]
    assert len(refreshes) == 2
    for r in refreshes:
        assert r["parent_token_hash"] == root_token
        assert r["token_family"] == fam_reuse

    # 3. Expired: Consistent token_hash and family across issuance, use, expiry, and rejected attempt
    expired_events = generated_datasets["expired-token"]["events"]
    exp_tok = expired_events[0]["token_hash"]
    exp_fam = expired_events[0]["token_family"]
    for e in expired_events:
        assert e["token_hash"] == exp_tok
        assert e["token_family"] == exp_fam

    # 4. Revoked: Consistent token_hash and family across session lifecycle
    revoked_events = generated_datasets["revoked-token"]["events"]
    rev_tok = revoked_events[0]["token_hash"]
    rev_fam = revoked_events[0]["token_family"]
    for e in revoked_events:
        assert e["token_hash"] == rev_tok
        assert e["token_family"] == rev_fam

    # 5. Concurrent Use: Same token presented by distinct device IDs
    concurrent_events = generated_datasets["concurrent-use"]["events"]
    conc_tok = concurrent_events[0]["token_hash"]
    conc_fam = concurrent_events[0]["token_family"]
    devices = {e["device_id"] for e in concurrent_events}
    assert len(devices) >= 2
    for e in concurrent_events:
        assert e["token_hash"] == conc_tok
        assert e["token_family"] == conc_fam

    # 6. Impossible Travel: Same token presented from distant country codes
    travel_events = generated_datasets["impossible-travel"]["events"]
    travel_tok = travel_events[0]["token_hash"]
    travel_fam = travel_events[0]["token_family"]
    countries = {e["country"] for e in travel_events if "country" in e}
    assert len(countries) >= 2
    for e in travel_events:
        assert e["token_hash"] == travel_tok
        assert e["token_family"] == travel_fam


def test_normal_scenario_lifecycle_condition(generated_datasets):
    """Verifies that normal.json contains only accepted events and no attack/anomaly signals."""
    events = generated_datasets["normal"]["events"]
    assert all(e["result"] == "accepted" for e in events)
    event_types = [e["event_type"] for e in events]
    assert "token_issued" in event_types
    assert "token_used" in event_types
    assert "token_refreshed" in event_types
    assert "logout" in event_types
    assert "suspicious_location" not in event_types
    assert "suspicious_device" not in event_types
    assert "replay_detected" not in event_types


def test_refresh_reuse_lifecycle_condition(generated_datasets):
    """Verifies that refresh-reuse.json triggers reuse detection in TokenFamilyCorrelator."""
    events = generated_datasets["refresh-reuse"]["events"]
    correlator = TokenFamilyCorrelator()
    for evt in events:
        correlator.process_event(evt)

    reuse_records = correlator.get_reuse_records()
    assert len(reuse_records) == 1
    record = reuse_records[0]
    assert record.attempted_event_id == "evt-reuse-005"
    assert record.token_hash == events[0]["token_hash"]


def test_expired_token_lifecycle_condition(generated_datasets):
    """Verifies that expired-token.json represents expiration and subsequent rejected use."""
    events = generated_datasets["expired-token"]["events"]
    correlator = TokenFamilyCorrelator()
    for evt in events:
        correlator.process_event(evt)

    # Correlator marks token as EXPIRED
    token_hash = events[0]["token_hash"]
    assert correlator.tokens[token_hash].status == TokenStatus.EXPIRED

    # Lifecycle includes expiration event and subsequent rejected attempt
    event_types = [e["event_type"] for e in events]
    assert "token_expired" in event_types
    last_event = events[-1]
    assert last_event["event_type"] == "token_used"
    assert last_event["result"] == "rejected"


def test_revoked_token_lifecycle_condition(generated_datasets):
    """Verifies that revoked-token.json represents revocation and subsequent rejected use."""
    events = generated_datasets["revoked-token"]["events"]
    correlator = TokenFamilyCorrelator()
    for evt in events:
        correlator.process_event(evt)

    token_hash = events[0]["token_hash"]
    assert correlator.tokens[token_hash].status == TokenStatus.REVOKED

    last_event = events[-1]
    assert last_event["event_type"] == "token_used"
    assert last_event["result"] == "rejected"


def test_concurrent_use_lifecycle_condition(generated_datasets):
    """Verifies concurrent-use.json demonstrates tight overlapping timestamps from distinct devices."""
    events = generated_datasets["concurrent-use"]["events"]
    dev_1_evt = [e for e in events if e["device_id"] == "device-workstation-office"][-1]
    dev_2_evt = [e for e in events if e["device_id"] == "device-rogue-clone"][0]

    t1 = datetime.strptime(dev_1_evt["time"], "%Y-%m-%dT%H:%M:%SZ")
    t2 = datetime.strptime(dev_2_evt["time"], "%Y-%m-%dT%H:%M:%SZ")
    diff_seconds = abs((t2 - t1).total_seconds())

    # Activity must occur within seconds
    assert diff_seconds <= 10
    event_types = [e["event_type"] for e in events]
    assert "suspicious_device" in event_types


def test_impossible_travel_lifecycle_condition(generated_datasets):
    """Verifies impossible-travel.json demonstrates distant locations within an impossible timeframe."""
    events = generated_datasets["impossible-travel"]["events"]
    in_evt = [e for e in events if e.get("country") == "IN"][-1]
    us_evt = [e for e in events if e.get("country") == "US"][0]

    t_in = datetime.strptime(in_evt["time"], "%Y-%m-%dT%H:%M:%SZ")
    t_us = datetime.strptime(us_evt["time"], "%Y-%m-%dT%H:%M:%SZ")
    diff_seconds = abs((t_us - t_in).total_seconds())

    # Distance between India and US within 5 minutes (300 seconds) is physically impossible
    assert diff_seconds <= 300
    event_types = [e["event_type"] for e in events]
    assert "suspicious_location" in event_types


def test_deterministic_reproducibility(tmp_path):
    """Verifies generation is 100% reproducible with the same seed, and changes with a different seed."""
    dir_1 = tmp_path / "run1"
    dir_2 = tmp_path / "run2"
    dir_3 = tmp_path / "run3"

    paths_1 = generate_all_datasets(output_dir=str(dir_1), seed=42)
    paths_2 = generate_all_datasets(output_dir=str(dir_2), seed=42)
    paths_3 = generate_all_datasets(output_dir=str(dir_3), seed=999)

    for sc_name in DATASET_SCENARIOS:
        with open(paths_1[sc_name], "r", encoding="utf-8") as f1, \
             open(paths_2[sc_name], "r", encoding="utf-8") as f2, \
             open(paths_3[sc_name], "r", encoding="utf-8") as f3:
            content_1 = f1.read()
            content_2 = f2.read()
            content_3 = f3.read()

            assert content_1 == content_2, f"Scenario '{sc_name}' is not identical with seed=42"
            assert content_1 != content_3, f"Scenario '{sc_name}' did not change with seed=999"


def test_no_raw_credentials_in_synthetic_data(generated_datasets):
    """Verifies synthetic datasets never contain raw JWT tokens, auth headers, or secret keys."""
    for sc_name, data in generated_datasets.items():
        events = data["events"]
        raw_dump = json.dumps(events)
        assert "Bearer " not in raw_dump
        assert "password" not in raw_dump.lower()
        assert "secret_key" not in raw_dump.lower()
