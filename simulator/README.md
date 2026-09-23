# TokenLine Local Attack Simulator

The Local Attack Simulator produces realistic, deterministic synthetic authentication event sequences designed to test the **Token-Family Correlator** and downstream detection modules without touching external networks or requiring real credentials.

---

## Architecture & Security Boundary

- **Zero Network Egress**: All scenarios run entirely locally with synthetic users, tokens, IP hashes, and device IDs.
- **Privacy-Preserving**: Only salted SHA-256 prefixes are emitted for tokens and IPs, strictly adhering to `schema/event.schema.json`.
- **Reproducible**: Every generator accepts a seed parameter for 100% reproducible test fixtures.

---

## Scenarios

| Scenario | Directory | Description | Triggered Correlator/Detection Signal |
|---|---|---|---|
| **Token Replay** | `simulator/replay/` | Issue token A, legitimate use, adversary re-presents token A from untrusted host. | `replay_detected` |
| **Refresh-Token Reuse** | `simulator/refresh-reuse/` | Issue token A, rotate A &rarr; B, adversary presents old token A to refresh again. | `token_refreshed` (flagged by Correlator as reuse) |
| **Use After Logout** | `simulator/revoked-token/` | Issue token A, user logs out / revokes session, adversary attempts to present token A. | `logout` &rarr; `token_used` (rejected) |
| **Concurrent Use** | `simulator/concurrent-use/` | Same token presented almost simultaneously from two distinct devices/IPs. | `suspicious_device` |
| **Impossible Travel** | `simulator/impossible-travel/` | Same token presented from distant geographical coordinates (e.g. IN to US) within 5 minutes. | `suspicious_location` |

---

## CLI Usage

### List Available Scenarios
```bash
python -m simulator --list
```

### Run a Single Scenario (Output JSON)
```bash
python -m simulator --scenario refresh-reuse --pretty
```

### Export All Scenarios to File
```bash
python -m simulator --all --output data/synthetic/all_attack_scenarios.json --pretty
```

### Stream Directly to Running Event Collector
```bash
python -m simulator --scenario replay --collector-url http://127.0.0.1:5000/events
```
