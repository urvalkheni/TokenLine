import argparse
import json
import sys
import os
import importlib.util
import requests
from typing import Dict, Type, List, Any, Optional

# Ensure repository root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from simulator.base import BaseScenarioGenerator


def _load_scenario_class(subfolder: str, class_name: str) -> Type[BaseScenarioGenerator]:
    """Loads a generator class from a folder with hyphens in the directory name."""
    module_path = os.path.join(os.path.dirname(__file__), subfolder, "generator.py")
    spec = importlib.util.spec_from_file_location(f"simulator_{subfolder.replace('-', '_')}", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load scenario from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, class_name)


ReplayScenarioGenerator = _load_scenario_class("replay", "ReplayScenarioGenerator")
RefreshReuseScenarioGenerator = _load_scenario_class("refresh-reuse", "RefreshReuseScenarioGenerator")
RevokedTokenScenarioGenerator = _load_scenario_class("revoked-token", "RevokedTokenScenarioGenerator")
ConcurrentUseScenarioGenerator = _load_scenario_class("concurrent-use", "ConcurrentUseScenarioGenerator")
ImpossibleTravelScenarioGenerator = _load_scenario_class("impossible-travel", "ImpossibleTravelScenarioGenerator")

# Mapping scenario names (both hyphen and underscore versions)
SCENARIO_REGISTRY: Dict[str, Type[BaseScenarioGenerator]] = {
    "replay": ReplayScenarioGenerator,
    "refresh-reuse": RefreshReuseScenarioGenerator,
    "refresh_reuse": RefreshReuseScenarioGenerator,
    "revoked-token": RevokedTokenScenarioGenerator,
    "revoked_token": RevokedTokenScenarioGenerator,
    "concurrent-use": ConcurrentUseScenarioGenerator,
    "concurrent_use": ConcurrentUseScenarioGenerator,
    "impossible-travel": ImpossibleTravelScenarioGenerator,
    "impossible_travel": ImpossibleTravelScenarioGenerator,
}

CANONICAL_SCENARIO_NAMES = [
    "replay",
    "refresh-reuse",
    "revoked-token",
    "concurrent-use",
    "impossible-travel",
]


def run_scenario(name: str, seed: int = 42) -> List[Dict[str, Any]]:
    """Instantiates and executes a scenario generator by name."""
    if name not in SCENARIO_REGISTRY:
        raise ValueError(f"Unknown scenario '{name}'. Available: {CANONICAL_SCENARIO_NAMES}")
    generator_cls = SCENARIO_REGISTRY[name]
    generator = generator_cls(seed=seed)
    return generator.generate()


def run_all_scenarios(seed: int = 42) -> Dict[str, List[Dict[str, Any]]]:
    """Runs all 5 attack scenarios deterministically."""
    results = {}
    for name in CANONICAL_SCENARIO_NAMES:
        results[name] = run_scenario(name, seed=seed)
    return results


def submit_to_collector(events: List[Dict[str, Any]], collector_url: str) -> bool:
    """Submits a list of generated synthetic events to the Event Collector."""
    print(f"Submitting {len(events)} events to Collector at {collector_url}...")
    success = 0
    for evt in events:
        try:
            res = requests.post(collector_url, json=evt, timeout=5)
            if res.status_code in [200, 201]:
                print(f"  [OK] {evt['event_id']} ({evt['event_type']}) -> Status {res.status_code}")
                success += 1
            else:
                print(f"  [FAILED] {evt['event_id']} -> Status {res.status_code}: {res.text}")
        except Exception as e:
            print(f"  [ERROR] {evt['event_id']} -> Connection error: {e}")
    print(f"Submission complete: {success}/{len(events)} accepted.")
    return success == len(events)


def main():
    parser = argparse.ArgumentParser(
        description="TokenLine Local Synthetic Attack Scenario Simulator"
    )
    parser.add_argument(
        "-s", "--scenario",
        choices=list(SCENARIO_REGISTRY.keys()),
        help="Specify scenario to run"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all five scenarios"
    )
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List available scenarios"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for deterministic generation (default: 42)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to save output events JSON file"
    )
    parser.add_argument(
        "-c", "--collector-url",
        help="Event Collector ingestion endpoint (e.g. http://127.0.0.1:5000/events)"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty print JSON output"
    )

    args = parser.parse_args()

    if args.list:
        print("Available attack simulation scenarios:")
        for name in CANONICAL_SCENARIO_NAMES:
            print(f"  - {name}")
        return

    if not args.scenario and not args.all:
        parser.print_help()
        return

    if args.all:
        all_events = run_all_scenarios(seed=args.seed)
        flat_events = []
        for s_name, evts in all_events.items():
            flat_events.extend(evts)

        if args.output:
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(flat_events, f, indent=2 if args.pretty else None)
            print(f"Saved {len(flat_events)} events across 5 scenarios to {args.output}")

        if args.collector_url:
            submit_to_collector(flat_events, args.collector_url)

        if not args.output and not args.collector_url:
            indent = 2 if args.pretty else None
            print(json.dumps(all_events, indent=indent))

    elif args.scenario:
        events = run_scenario(args.scenario, seed=args.seed)
        
        if args.output:
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(events, f, indent=2 if args.pretty else None)
            print(f"Saved {len(events)} events for scenario '{args.scenario}' to {args.output}")

        if args.collector_url:
            submit_to_collector(events, args.collector_url)

        if not args.output and not args.collector_url:
            indent = 2 if args.pretty else None
            print(json.dumps(events, indent=indent))


if __name__ == "__main__":
    main()
