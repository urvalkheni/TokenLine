# TokenLine Local Attack Simulator & Dataset Generator

The Local Attack Simulator and Synthetic Dataset Generator produce realistic, deterministic authentication event sequences designed to test the **Token-Family Correlator**, detection rules, and security pipelines without touching external networks or requiring real credentials.

---

## 1. Architecture & Security Boundary

- **Zero Network Egress**: All scenarios run entirely locally with synthetic users, tokens, IP hashes, and device IDs.
- **Privacy-Preserving**: Only salted SHA-256 prefixes are emitted for tokens and IPs, strictly adhering to [`schema/event.schema.json`](../schema/event.schema.json).
- **Reproducible**: Every generator accepts a seed parameter for 100% reproducible test fixtures.
- **Schema Validated**: Every generated event is validated against `schema/event.schema.json`.
- **Controlled Benchmark Context**: These scenarios are designed for testing, calibration, and educational demonstration. Passing synthetic benchmark scenarios demonstrates pipeline logic correctness, but is not proof of production detection efficacy against adversarial evasion.

---

## 2. Scenarios & Synthetic Datasets

The generator produces canonical datasets in `data/synthetic/`:

| Scenario | Directory / Module | Output File | Description | Triggered Correlator/Detection Signal |
| :--- | :--- | :--- | :--- | :--- |
| **Normal Lifecycle** | `simulator/normal/` | [`data/synthetic/normal.json`](../data/synthetic/normal.json) | Baseline token issuance, legitimate use, refresh rotation, and logout. | None (All `accepted`) |
| **Refresh-Token Reuse** | `simulator/refresh-reuse/` | [`data/synthetic/refresh-reuse.json`](../data/synthetic/refresh-reuse.json) | Issue token A, rotate A &rarr; B, adversary presents rotated token A again. | `RULE-TOKEN-REUSE` (`critical`, `rejected`) |
| **Expired Token** | `simulator/expired-token/` | [`data/synthetic/expired-token.json`](../data/synthetic/expired-token.json) | Token issuance, legitimate use, expiry threshold reached, and invalid usage attempt. | `RULE-EXPIRED-USE` (`high`, `rejected`) |
| **Use After Logout** | `simulator/revoked-token/` | [`data/synthetic/revoked-token.json`](../data/synthetic/revoked-token.json) | Issue token A, user logs out / revokes session, adversary attempts to present token A. | `RULE-REVOKED-USE` (`high`, `rejected`) |
| **Concurrent Use** | `simulator/concurrent-use/` | [`data/synthetic/concurrent-use.json`](../data/synthetic/concurrent-use.json) | Same token presented almost simultaneously from two distinct devices/IPs. | `RULE-CONCURRENT-USE` (`high`) |
| **Impossible Travel** | `simulator/impossible-travel/` | [`data/synthetic/impossible-travel.json`](../data/synthetic/impossible-travel.json) | Same token presented from distant geographical coordinates (e.g. IN to US) within 5 minutes. | `RULE-IMPOSSIBLE-TRAVEL` (`high`) |
| **Token Replay** | `simulator/replay/` | Synthetic Generator | Intercepted token replayed from an unauthorized host. | Replay detection signal |

---

## 3. Generating Datasets

### Generate All Datasets (Default: `data/synthetic/`)
```bash
python scripts/generate_datasets.py --seed 42
```
or via the simulator module:
```bash
python -m simulator --generate-datasets --seed 42
```

### Specify Output Directory
```bash
python scripts/generate_datasets.py --output-dir path/to/datasets --seed 42
```

### Generate a Single Specific Scenario
```bash
python scripts/generate_datasets.py --scenario refresh-reuse
```

### List Available Datasets
```bash
python scripts/generate_datasets.py --list
```

---

## 4. Running Scenarios in CLI

### List Available Simulation Scenarios
```bash
python -m simulator --list
```

### Run a Single Scenario (Output JSON)
```bash
python -m simulator --scenario normal --pretty
```

### Export All Scenarios to a Single Combined File
```bash
python -m simulator --all --output data/synthetic/all_attack_scenarios.json --pretty
```

### Stream Events Directly to Running Collector
```bash
python -m simulator --scenario refresh-reuse --collector-url http://127.0.0.1:5000/events
```

---

## 5. Testing & Evaluation

- **Correlator Validation**: Run `pytest tests/scenarios/test_synthetic_datasets.py` to ensure schema adherence, correct rotation links, and deterministic reproducibility.
- **Rule Verification**: Verify detection rules against `refresh-reuse.json`, `expired-token.json`, `revoked-token.json`, `concurrent-use.json`, and `impossible-travel.json`.
- **Baseline Calibration**: Use `normal.json` to verify that false alert rates are zero during benign token lifecycles.
- **Classification Metrics**: Run `pytest tests/unit/test_alert_standard_and_evaluation.py` to evaluate precision, recall, specificity, and F1 scores against labeled incident benchmarks.
