# TokenLine Attack & Lifecycle Scenarios

This document details the synthetic token lifecycle scenarios and attack patterns modeled in TokenLine, the generated datasets stored in `data/synthetic/`, and how they are used for testing and detection research.

---

## 1. Overview & Data Security Principles

TokenLine tests token lineage tracking and anomaly detection using **100% synthetic event sequences**. 
- **Zero Sensitive Data**: No real access tokens, refresh tokens, passwords, session cookies, or personal identifiers are ever stored or emitted.
- **Privacy-Preserving Identifiers**: Token hashes (`token_hash`, `parent_token_hash`) and network hashes (`ip_hash`) are derived deterministically using keyed/salted SHA-256 prefixes (e.g. `hash_...`).
- **Schema Strictness**: All events adhere strictly to [`schema/event.schema.json`](../schema/event.schema.json).
- **Reproducible Test Fixtures**: All datasets are deterministically generated from customizable random seeds (default: seed `42`).
- **Benchmark Context**: Synthetic scenarios serve as reproducible functional test fixtures for development and automated evaluation; they do not represent proof of production detection efficacy against sophisticated attackers.

---

## 2. Dataset Locations

The generated synthetic datasets are saved in the `data/synthetic/` directory:

| Dataset Filename | Scenario | Event Count | Anomaly Signal | Description |
| :--- | :--- | :--- | :--- | :--- |
| [`normal.json`](../data/synthetic/normal.json) | Normal Lifecycle | 6 | None (All Accepted) | Baseline issuance, access, rotation, and logout. |
| [`refresh-reuse.json`](../data/synthetic/refresh-reuse.json) | Refresh-Token Reuse | 5 | `RULE-TOKEN-REUSE` / rejected refresh | Malicious presentation of already-rotated parent token. |
| [`expired-token.json`](../data/synthetic/expired-token.json) | Expired Token | 4 | `RULE-EXPIRED-USE` / rejected use | Legitimate use, expiry threshold reached, and invalid usage attempt. |
| [`revoked-token.json`](../data/synthetic/revoked-token.json) | Revoked Token | 4 | `RULE-REVOKED-USE` / rejected use | Active session revoked by user logout, followed by rejected access. |
| [`concurrent-use.json`](../data/synthetic/concurrent-use.json) | Concurrent Use | 4 | `RULE-CONCURRENT-USE` | Same token presented concurrently across distinct physical devices. |
| [`impossible-travel.json`](../data/synthetic/impossible-travel.json) | Impossible Travel | 3 | `RULE-IMPOSSIBLE-TRAVEL` | Distant regional access (IN &rarr; US) within a 4-minute window. |

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
* **Detection Trigger**: `TokenFamilyCorrelator` detects that Token A's record already has `is_rotated = True`. It logs a `TokenReuseRecord` and `AlertRecord` referencing the attacker's event ID (`evt-reuse-005`), revokes the family, and rejects the refresh request (`result: rejected`).

---

### 3. Expired Token (`expired-token.json`)
* **Lifecycle Mechanism**: Token usage past its defined Time-To-Live (TTL):
  1. `token_issued`: User authenticates and receives an active token at T = 0.
  2. `token_used`: Legitimate use within active lifespan at T + 5 minutes.
  3. `token_expired`: Token service marks the token as expired at T + 60 minutes.
  4. `token_used`: Client presents the expired token at T + 61 minutes (`result: rejected`).
* **Detection Trigger**: Correlator updates token status to `TokenStatus.EXPIRED` and logs `RULE-EXPIRED-USE`.

---

### 4. Revoked Token / Use After Logout (`revoked-token.json`)
* **Lifecycle Mechanism**: Presentation of credentials after explicit session termination:
  1. `token_issued`: Token issued upon user authentication at T = 0.
  2. `token_used`: Legitimate access to protected resource at T + 5 minutes.
  3. `logout`: User terminates session at T + 15 minutes.
  4. `token_used`: Adversary or lingering client attempts to use the revoked token at T + 16 minutes (`result: rejected`).
* **Detection Trigger**: Session registry marks token as `TokenStatus.REVOKED`. The subsequent access request triggers `RULE-REVOKED-USE`.

---

### 5. Concurrent Use (`concurrent-use.json`)
* **Attack Mechanism**: Stolen token active simultaneously from multiple locations or clients:
  1. `token_issued`: Token issued to legitimate workstation (`device-workstation-office`, US IP) at T = 0.
  2. `token_used`: Legitimate access from office workstation at T = 60s.
  3. `token_used`: Rogue client (`device-rogue-clone`, DE IP) presents the exact same token hash at T = 65s (5-second gap).
  4. Correlator flags concurrent access across disjoint device fingerprints (`RULE-CONCURRENT-USE`).
* **Detection Trigger**: Same active token presented from conflicting `device_id` or `ip_hash` values within $\Delta t \le 60\text{s}$.

---

### 6. Impossible Travel (`impossible-travel.json`)
* **Attack Mechanism**: Velocity anomaly where physical transit speed exceeds realistic aircraft travel:
  1. `token_issued`: User authenticates from India (`country: IN`) at T = 0.
  2. `token_used`: User performs actions from India at T = 60s.
  3. Same token presented 4 minutes later (T = 300s) from the United States (`country: US`).
* **Detection Trigger**: User activity across distinct countries in 240 seconds triggers `RULE-IMPOSSIBLE-TRAVEL`.

---

## 4. Running the Synthetic Dataset Generator

### Generate All Datasets via Dedicated Script
```bash
python scripts/generate_datasets.py --seed 42 --output-dir data/synthetic
```

### Stream Dataset to Running Collector
```bash
python scripts/submit_dataset.py
```
