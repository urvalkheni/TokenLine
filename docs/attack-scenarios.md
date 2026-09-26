# TokenLine Attack & Lifecycle Scenarios

This document details the synthetic token lifecycle scenarios and attack patterns modeled in TokenLine, the generated datasets stored in `data/synthetic/`, and how they are used for testing and detection research.

---

## 1. Overview & Data Security Principles

TokenLine tests token lineage tracking and anomaly detection using **100% synthetic event sequences**. 
- **Zero Sensitive Data**: No real access tokens, refresh tokens, passwords, session cookies, or personal identifiers are ever stored or emitted.
- **Privacy-Preserving Identifiers**: Token hashes (`token_hash`, `parent_token_hash`) and network hashes (`ip_hash`) are derived deterministically using keyed/salted SHA-256 prefixes (e.g. `hash_...`).
- **Schema Strictness**: All events adhere strictly to [`schema/event.schema.json`](file:///d:/TokenLine/TokenLine/schema/event.schema.json).
- **Reproducible Test Fixtures**: All datasets are deterministically generated from customizable random seeds (default: seed `42`).

---

## 2. Dataset Locations

The generated synthetic datasets are saved in the `data/synthetic/` directory:

| Dataset Filename | Scenario | Event Count | Anomaly Signal | Description |
|---|---|---|---|---|
| [`normal.json`](file:///d:/TokenLine/TokenLine/data/synthetic/normal.json) | Normal Lifecycle | 6 | None (All Accepted) | Baseline issuance, access, rotation, and logout. |
| [`refresh-reuse.json`](file:///d:/TokenLine/TokenLine/data/synthetic/refresh-reuse.json) | Refresh-Token Reuse | 5 | `TokenReuseRecord` / rejected refresh | Malicious presentation of already-rotated parent token. |
| [`expired-token.json`](file:///d:/TokenLine/TokenLine/data/synthetic/expired-token.json) | Expired Token | 4 | `token_expired` &rarr; rejected use | Legitimate use, expiry threshold reached, and invalid usage attempt. |
| [`revoked-token.json`](file:///d:/TokenLine/TokenLine/data/synthetic/revoked-token.json) | Revoked Token | 4 | `logout` &rarr; rejected use | Active session revoked by user logout, followed by rejected access. |
| [`concurrent-use.json`](file:///d:/TokenLine/TokenLine/data/synthetic/concurrent-use.json) | Concurrent Use | 4 | `suspicious_device` | Same token presented concurrently across distinct physical devices. |
| [`impossible-travel.json`](file:///d:/TokenLine/TokenLine/data/synthetic/impossible-travel.json) | Impossible Travel | 3 | `suspicious_location` | Distant regional access (IN &rarr; US) within a 4-minute window. |

---

## 3. Scenario Descriptions & Detection Signatures

### 1. Normal Lifecycle (`normal.json`)
* **Behavior**: Simulates an ordinary, non-adversarial user session:
  1. `token_issued`: User logs in at `/api/auth/login` and receives Token A (`result: accepted`).
  2. `token_used`: User queries `/api/v1/profile` with Token A (`result: accepted`).
  3. `token_used`: User accesses `/api/v1/dashboard` with Token A (`result: accepted`).
  4. `token_refreshed`: Token A reaches refresh lifespan; user rotates to Token B with `parent_token_hash = Token A` (`result: accepted`).
  5. `token_used`: User uses rotated Token B to access `/api/v1/feed` (`result: accepted`).
  6. `logout`: User explicitly signs out at `/api/auth/logout`, concluding the session (`result: accepted`).
* **Expected System State**: All events accepted. In `TokenFamilyCorrelator`, Token A is marked `ROTATED`, Token B is marked `REVOKED`, and the chain is `[Token A, Token B]` with 0 reuse records.

---

### 2. Refresh-Token Reuse (`refresh-reuse.json`)
* **Attack Mechanism**: RFC 6749 / RFC 6819 refresh token rotation bypass attempt:
  1. Legitimate user logs in (Token A issued).
  2. Legitimate user rotates Token A &rarr; Token B via `/api/auth/refresh`.
  3. An adversary who previously compromised the rotated Token A attempts to present it at `/api/auth/refresh`.
* **Lineage & Relationship**: Both the legitimate rotation event and the adversarial attempt reference `parent_token_hash = Token A`.
* **Detection Trigger**: `TokenFamilyCorrelator` detects that Token A's record already has `is_rotated = True`. It logs a `TokenReuseRecord` referencing the attacker's event ID (`evt-reuse-005`), while the collector or IdP rejects the refresh request (`result: rejected`).

---

### 3. Expired Token (`expired-token.json`)
* **Lifecycle Mechanism**: Token usage past its defined Time-To-Live (TTL):
  1. `token_issued`: User authenticates and receives an active token at T = 0.
  2. `token_used`: Legitimate use within active lifespan at T + 5 minutes.
  3. `token_expired`: IdP / token service marks the token as expired at T + 60 minutes.
  4. `token_used`: Client presents the expired token at T + 61 minutes (`result: rejected`).
* **Detection Trigger**: Correlator updates token status to `TokenStatus.EXPIRED`. Authorization middleware denies API access with HTTP 401 Unauthorized.

---

### 4. Revoked Token / Use After Logout (`revoked-token.json`)
* **Lifecycle Mechanism**: Presentation of credentials after explicit session termination:
  1. `token_issued`: Token issued upon user authentication at T = 0.
  2. `token_used`: Legitimate access to protected resource at T + 5 minutes.
  3. `logout`: User terminates session at T + 15 minutes.
  4. `token_used`: Adversary or lingering client attempts to use the revoked token at T + 16 minutes (`result: rejected`).
* **Detection Trigger**: Session registry marks token as `TokenStatus.REVOKED`. The subsequent access request is denied.

---

### 5. Concurrent Use (`concurrent-use.json`)
* **Attack Mechanism**: Stolen token active simultaneously from multiple locations or clients:
  1. `token_issued`: Token issued to legitimate workstation (`device-workstation-office`, US IP) at T = 0.
  2. `token_used`: Legitimate access from office workstation at T = 60s.
  3. `token_used`: Rogue client (`device-rogue-clone`, DE IP) presents the exact same token hash at T = 65s (5-second gap).
  4. `suspicious_device`: Security engine flags concurrent access across disjoint device fingerprints and rejects subsequent action (`result: rejected`).
* **Detection Trigger**: Same active token presented from conflicting `device_id` and `ip_hash` values within a sub-minute threshold.

---

### 6. Impossible Travel (`impossible-travel.json`)
* **Attack Mechanism**: Velocity anomaly where physical transit speed exceeds realistic aircraft travel:
  1. `token_issued`: User authenticates from India (`country: IN`) at T = 0.
  2. `token_used`: User performs actions from India at T = 60s.
  3. `suspicious_location`: Same token presented 4 minutes later (T = 300s) from the United States (`country: US`).
* **Detection Trigger**: Geographic distance between Mumbai (`IN`) and New York (`US`) is ~12,500 km. Crossing this distance in 240 seconds requires a speed exceeding 180,000 km/h, which triggers immediate velocity threshold alerts (`result: rejected`).

---

## 4. Running the Synthetic Dataset Generator

### Generate All Datasets via Dedicated Script
```bash
python scripts/generate_datasets.py --seed 42 --output-dir data/synthetic
```

### Generate via Simulator CLI
```bash
python -m simulator --generate-datasets --seed 42
```

### Generate a Single Specific Scenario
```bash
python scripts/generate_datasets.py --scenario refresh-reuse
```

### Verify Conformance via Pytest
```bash
py -m pytest tests/scenarios/test_synthetic_datasets.py -v
```

---

## 5. Research & Detection Testing Applications

1. **Token Lineage Benchmark**: Feed datasets into correlation engines to verify parent/child tree reconstruction without false positives.
2. **False Alert Rate Calibration**: Baseline against `normal.json` to verify zero false positives on standard rotation lifecycles.
3. **Stream Pipeline Validation**: Ingest `data/synthetic/*.json` via `scripts/submit_dataset.py` into Kafka, Event Collector, or Elasticsearch pipelines.
4. **Machine Learning / Anomaly Models**: Train sequence models (Markov models, LSTMs, rule engines) on normal vs. anomalous temporal patterns.
