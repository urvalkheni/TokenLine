# TokenLine Architecture: Token-Family Correlation

This document explains the architecture of the **Token-Family Correlator**, the underlying data model, rotation tracking, reuse condition detection, and how correlation integrates with synthetic datasets.

---

## 1. What a Token Family Is

In modern authentication systems implementing refresh-token rotation (such as RFC 6749 / RFC 6819), issuing a new access and refresh token pair invalidates the preceding refresh token. 

A **Token Family** represents the complete cryptographic lineage of tokens issued across a single user session. Rather than viewing each refresh event as an isolated transaction, TokenLine groups all ancestor and descendant tokens under a single logical identifier: `token_family`.

```text
Token Family (e.g., family-session-01):
  Token A (Root / Initial Login)
     │
     ▼ (Rotated via /api/auth/refresh)
  Token B (Child of A)
     │
     ▼ (Rotated via /api/auth/refresh)
  Token C (Child of B, Current Active Token)
```

By tracking tokens as a family:
- Security analysts can inspect the full chronological life of a session.
- Anomaly detectors can immediately flag when an older, superseded token from the family is re-presented by an adversary.

---

## 2. Representation of Parent/Child Relationships

TokenLine models parent/child relationships using privacy-preserving hashes defined in [`schema/event.schema.json`](file:///d:/TokenLine/TokenLine/schema/event.schema.json):

* `token_hash`: The unique, privacy-preserving SHA-256 hash representing the newly issued token.
* `parent_token_hash`: The hash of the predecessor token presented to the authorization server to authorize the rotation.
* `token_family`: The session lineage group identifier.

### Schema Representation in Events
```json
{
  "event_id": "evt-003",
  "event_type": "token_refreshed",
  "time": "2026-08-16T10:30:00Z",
  "user_id": "user-synthetic",
  "token_hash": "hash_child_B",
  "parent_token_hash": "hash_parent_A",
  "token_family": "family-session-01",
  "ip_hash": "hash_ip_workstation",
  "device_id": "device-workstation",
  "result": "accepted"
}
```

In memory ([`TokenRecord`](file:///d:/TokenLine/TokenLine/backend/correlator/models.py#L15)) and in the database ([`TokenFamilyMember`](file:///d:/TokenLine/TokenLine/backend/collector/db.py)):
- The parent token (`hash_parent_A`) updates its state:
  - `status = TokenStatus.ROTATED`
  - `is_rotated = True`
  - `superseded_by = "hash_child_B"`
  - `rotated_at = timestamp`
- The child token (`hash_child_B`) records:
  - `parent_token_hash = "hash_parent_A"`
  - `status = TokenStatus.ACTIVE`
  - `token_family = "family-session-01"`

---

## 3. How Refresh-Token Rotation Is Correlated

The correlator processes lifecycle events sequentially:

1. **Initial Issuance (`token_issued`)**:
   - The root token is registered in `self.tokens` with `parent_token_hash = None` and `status = TokenStatus.ACTIVE`.
   - The token is added to the family list `self.families[token_family]`.

2. **Rotation (`token_refreshed`)**:
   - The correlator extracts `parent_token_hash` from the incoming event.
   - If the parent token is known, the family identifier `token_family` is propagated to the new child token.
   - If the parent is not yet rotated, its status updates to `ROTATED` and its `superseded_by` pointer links to the child token.
   - The child token joins the family with `parent_token_hash` pointing to the predecessor.

3. **Reconstructing Full Lineage Chains (`reconstruct_chain`)**:
   - Given any token in the chain (e.g. `Token B` or `Token C`) or the `token_family` identifier, the correlator traverses backward via `parent_token_hash` until reaching the root ancestor.
   - It then walks forward via `superseded_by` links to reconstruct the full ordered chain:
     $$\text{Token A} \longrightarrow \text{Token B} \longrightarrow \text{Token C}$$

4. **Multi-Family Isolation**:
   - Unrelated user sessions (e.g. `Family 1: A -> B -> C` and `Family 2: X -> Y -> Z`) maintain completely isolated lineage graphs. No tokens are cross-linked between distinct family IDs.

---

## 4. How Refresh-Token Reuse Is Identified

Refresh-token reuse occurs when an adversary steals a rotated refresh token and subsequently attempts to present it to issue a new token.

```text
Legitimate Flow:  Token A  ──── refresh ────►  Token B (Active)
                                                  ▲
Adversary Flow:   Token A  ──── refresh ────►  Token C (Attempted Reuse!)
                    │
                    ▼
          [REUSE FLAGGED!]
          Token A is already rotated.
          Legitimate child remains Token B.
```

### Detection & State Preservation Mechanism:
1. When a `token_refreshed` event is evaluated, the correlator inspects the token presented for rotation (`parent_token_hash`).
2. It queries `self.tokens[parent_token_hash]`.
3. If `parent.is_rotated == True`:
   - A refresh-token reuse condition is detected.
   - The correlator instantiates a [`TokenReuseRecord`](file:///d:/TokenLine/TokenLine/backend/correlator/models.py#L47) containing:
     - `token_hash`: The reused parent token.
     - `token_family`: The affected family.
     - `reused_at`: Timestamp of the reuse attempt.
     - `attempted_event_id`: The event ID representing the malicious attempt.
     - `chain_context`: Snapshot of the legitimate rotation chain up to that moment.
   - **Protection of Lineage**: The correlator retains the original legitimate child link (`parent.superseded_by == Token B`) and does not overwrite it with the attacker's rejected attempt.
   - The reuse record is retained in `self.reuse_records` for consumption by the downstream detection engine.

---

## 5. Correlator Usage with Synthetic Datasets

The correlator is designed to consume synthetic datasets generated by [`scripts/generate_datasets.py`](file:///d:/TokenLine/TokenLine/scripts/generate_datasets.py):

### 1. In-Memory Standalone Processing
```python
import json
from backend.correlator import TokenFamilyCorrelator

correlator = TokenFamilyCorrelator()

# Process normal lifecycle
with open("data/synthetic/normal.json", "r") as f:
    normal_events = json.load(f)

for evt in normal_events:
    correlator.process_event(evt)

# Reconstruct rotation chain
chain = correlator.reconstruct_chain("hash_a51dd1f0ff5c")
# Returns: ["hash_a51dd1f0ff5c", "hash_307eaa20d7cb"]
```

### 2. Reuse Scenario Verification
```python
with open("data/synthetic/refresh-reuse.json", "r") as f:
    reuse_events = json.load(f)

for evt in reuse_events:
    correlator.process_event(evt)

reuse_records = correlator.get_reuse_records()
# Returns 1 TokenReuseRecord flagged on evt-reuse-005
```

### 3. Database-Backed Processing
```python
from backend.collector.correlator import process_event_file

# Synchronizes directly with SQLite tables token_family_members and token_reuse_records
process_event_file("data/synthetic/refresh-reuse.json")
```
