import os
import sys
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional, Type

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from simulator.base import BaseScenarioGenerator, EVENT_SCHEMA
from simulator.runner import _load_scenario_class

# Dynamically load the generators from their directories
NormalScenarioGenerator = _load_scenario_class("normal", "NormalScenarioGenerator")
RefreshReuseScenarioGenerator = _load_scenario_class("refresh-reuse", "RefreshReuseScenarioGenerator")
ExpiredTokenScenarioGenerator = _load_scenario_class("expired-token", "ExpiredTokenScenarioGenerator")
RevokedTokenScenarioGenerator = _load_scenario_class("revoked-token", "RevokedTokenScenarioGenerator")
ConcurrentUseScenarioGenerator = _load_scenario_class("concurrent-use", "ConcurrentUseScenarioGenerator")
ImpossibleTravelScenarioGenerator = _load_scenario_class("impossible-travel", "ImpossibleTravelScenarioGenerator")

DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "synthetic")

DATASET_CONFIG: Dict[str, Dict[str, Any]] = {
    "normal": {
        "filename": "normal.json",
        "class": NormalScenarioGenerator,
        "description": "Normal token issuance, usage, refresh lifecycle, and clean logout without anomalies.",
    },
    "refresh-reuse": {
        "filename": "refresh-reuse.json",
        "class": RefreshReuseScenarioGenerator,
        "description": "Simulation of refresh-token reuse on a rotated parent token, triggering reuse detection.",
    },
    "expired-token": {
        "filename": "expired-token.json",
        "class": ExpiredTokenScenarioGenerator,
        "description": "Lifecycle events for an expired token followed by rejected invalid usage attempts.",
    },
    "revoked-token": {
        "filename": "revoked-token.json",
        "class": RevokedTokenScenarioGenerator,
        "description": "Token issuance, explicit session revocation/logout, and subsequent rejected use.",
    },
    "concurrent-use": {
        "filename": "concurrent-use.json",
        "class": ConcurrentUseScenarioGenerator,
        "description": "Concurrent presentation of the same token from multiple distinct devices/locations.",
    },
    "impossible-travel": {
        "filename": "impossible-travel.json",
        "class": ImpossibleTravelScenarioGenerator,
        "description": "Token usage from geographically distant regions within an impossibly brief timeframe.",
    },
}

DATASET_SCENARIOS = list(DATASET_CONFIG.keys())


def generate_scenario_dataset(
    scenario_name: str,
    seed: int = 42,
    base_time: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """Generates and schema-validates a single synthetic dataset by scenario name."""
    if scenario_name not in DATASET_CONFIG:
        raise ValueError(f"Unknown scenario '{scenario_name}'. Available: {DATASET_SCENARIOS}")
    
    generator_cls: Type[BaseScenarioGenerator] = DATASET_CONFIG[scenario_name]["class"]
    generator = generator_cls(seed=seed, base_time=base_time)
    events = generator.generate()

    # Re-validate every event against JSON Schema to guarantee conformance
    for evt in events:
        generator.validate_event(evt)

    return events


def generate_all_datasets(
    output_dir: Optional[str] = None,
    seed: int = 42,
    base_time: Optional[datetime] = None,
    indent: int = 2
) -> Dict[str, str]:
    """
    Generates all six synthetic token lifecycle datasets and writes them to disk.
    
    Returns a mapping of scenario name to absolute file path written.
    """
    target_dir = os.path.abspath(output_dir or DEFAULT_OUTPUT_DIR)
    os.makedirs(target_dir, exist_ok=True)
    
    written_files: Dict[str, str] = {}

    for scenario_name, config in DATASET_CONFIG.items():
        events = generate_scenario_dataset(scenario_name, seed=seed, base_time=base_time)
        filepath = os.path.join(target_dir, config["filename"])

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=indent)

        written_files[scenario_name] = filepath

    return written_files


def main():
    parser = argparse.ArgumentParser(
        description="TokenLine Synthetic Token Lifecycle Dataset Generator"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for deterministic generation (default: 42)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to save generated JSON files (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "-s", "--scenario",
        choices=DATASET_SCENARIOS,
        help="Generate only a specific scenario instead of all six"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available synthetic dataset scenarios"
    )
    parser.add_argument(
        "--no-pretty",
        action="store_true",
        help="Disable indentation in JSON output"
    )

    args = parser.parse_args()

    if args.list:
        print("Available Synthetic Lifecycle Datasets:")
        for name, cfg in DATASET_CONFIG.items():
            print(f"  - {name:18} -> {cfg['filename']:24} ({cfg['description']})")
        return

    indent = None if args.no_pretty else 2

    if args.scenario:
        events = generate_scenario_dataset(args.scenario, seed=args.seed)
        os.makedirs(args.output_dir, exist_ok=True)
        filename = DATASET_CONFIG[args.scenario]["filename"]
        filepath = os.path.join(args.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=indent)
        print(f"Successfully generated scenario '{args.scenario}' ({len(events)} events) -> {filepath}")
    else:
        results = generate_all_datasets(output_dir=args.output_dir, seed=args.seed, indent=indent)
        print(f"Successfully generated {len(results)} synthetic datasets with seed={args.seed}:")
        for sc_name, path in results.items():
            print(f"  - {sc_name:18} -> {path}")


if __name__ == "__main__":
    main()
