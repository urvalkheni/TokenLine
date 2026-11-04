# Token-Family Correlator & Detection Engine

The Token-Family Correlator (`backend.correlator`) reconstructs refresh-token parent/child chains ("token families"), manages token lifecycle states, evaluates anomaly detection rules, and generates explainable security alerts from events ingested by the Event Collector.

---

## 1. Architecture

The correlation system is built around the unified `TokenFamilyCorrelator` engine ([`backend/correlator/engine.py`](engine.py)):

1. **State-Machine Model**:
   - Manages token statuses: `ACTIVE`, `ROTATED`, `REUSED`, `REVOKED`, `EXPIRED`.
   - Traverses parent/child token lineage chains (`reconstruct_chain`) from root tokens to current leaves.
   - Provides ancestor and descendant queries (`get_ancestors`, `get_descendants`).
   - Maintains token and session state in memory for high-performance processing.

2. **Detection Rules Engine**:
   Evaluates 5 canonical security detection rules:
   - `RULE-TOKEN-REUSE` (`TL-RULE-001`): Detects reuse attempts on previously rotated refresh tokens (`critical` severity). Revokes the entire token family upon detection.
   - `RULE-REVOKED-USE` (`TL-RULE-002`): Detects token presentations after explicit logout or cascade revocation (`high` severity). Accounts for out-of-order event timestamps.
   - `RULE-EXPIRED-USE` (`TL-RULE-003`): Detects token usage past configured expiration timestamps (`high` severity).
   - `RULE-CONCURRENT-USE` (`TL-RULE-004`): Detects identical tokens presented concurrently ($\Delta t \le 60\text{s}$) across distinct physical devices or IP addresses (`high` severity).
   - `RULE-IMPOSSIBLE-TRAVEL` (`TL-RULE-005`): Detects consecutive user or token activity originating from differing countries within a 5-minute window ($\Delta t \le 300\text{s}$) (`high` severity).

3. **Database Synchronization & Alert Deduplication**:
   - Synchronizes token family memberships to the `token_family_members` table.
   - Persists detected reuse records to `token_reuse_records`.
   - Records standardized, explainable `AlertRecord` entries into the `alerts` table with unique deduplication fingerprints (`uq_alerts_dedup`).
   - Supports atomic transactions via `correlator_transaction()`.

4. **Standardized Evaluation Framework**:
   [`backend/correlator/evaluator.py`](evaluator.py) provides incident-level classification evaluation calculating:
   - True Positives ($TP$), False Positives ($FP$), True Negatives ($TN$), False Negatives ($FN$)
   - Precision, Recall, Specificity, and F1-score
   - Explicit handling of zero-denominator cases (`None` / `N/A`)

---

## 2. Domain & Data Models

### In-Memory State Models (`backend.correlator.models`)
- `TokenRecord`: In-memory metadata, rotation state, timestamps, and status.
- `TokenReuseRecord`: Legacy and compatibility model for refresh-token reuse incidents.
- `DetectionRecord`: Unified detection record for any flagged rule violation.
- `AlertRecord`: Standardized alert model containing ID, rule ID, severity, title, explanation, event references, evidence JSON, status (`open`, `acknowledged`, `resolved`), and deduplication fingerprint.
- `TokenStatus`: Enum representing lifecycle states (`active`, `rotated`, `reused`, `revoked`, `expired`).

### Database Persistence (`backend.collector.db`)
- `token_family_members`: SQL table tracking persistent token family links and rotation timestamps.
- `token_reuse_records`: SQL table storing reuse events with unique index `(token_hash, attempted_event_id)`.
- `alerts`: SQL table storing explainable security alerts with unique index on `dedup_fingerprint`.

---

## 3. Usage Examples

### Standalone In-Memory Correlator
```python
from backend.correlator import TokenFamilyCorrelator

correlator = TokenFamilyCorrelator()
correlator.process_event({
    "event_id": "evt-1",
    "event_type": "token_issued",
    "time": "2026-08-16T10:00:00Z",
    "user_id": "user-1",
    "token_hash": "a4d3b8f1c29e",
    "token_family": "family-1",
    "ip_hash": "f3b29c9e8d1a",
    "device_id": "device-1",
    "result": "accepted"
})

chain = correlator.reconstruct_chain("a4d3b8f1c29e")
alerts = correlator.get_alerts()
```

### Database-Backed Transactional Processing
```python
from backend.correlator import process_event, reconstruct_chain, correlator_transaction
from backend.collector.db import get_session

db_session = get_session()
try:
    with correlator_transaction():
        process_event(event_data, db_session=db_session)
        chain = reconstruct_chain("a4d3b8f1c29e", db_session=db_session)
finally:
    db_session.close()
```

---

## 4. Known Detection Limitations

1. **Risk Signals vs. Compromise**: Alerts represent heuristic risk signals, not verified compromises. Legitimate user actions—such as VPN toggling or switching between Wi-Fi and mobile data—can trigger `RULE-IMPOSSIBLE-TRAVEL` or `RULE-CONCURRENT-USE`.
2. **Coarse Geolocation**: Impossible travel checks country differences rather than Haversine spherical transit velocity.
3. **Sliding Window Lifetime**: Concurrent use and travel window tracking reside in memory; process restarts clear transient window history unless re-evaluated.
