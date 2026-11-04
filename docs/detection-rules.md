# TokenLine Detection Rules & Anomaly Signatures

This document defines the core detection rules implemented and evaluated against synthetic token lifecycle datasets and event streams.

---

## 1. Detection Rule Matrix

| Rule ID | Canonical Name | Target Dataset | Input Event Type | Condition & Logic | Severity & Emitted Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `TL-RULE-001`<br>`(RULE-TOKEN-REUSE)` | **Refresh-Token Reuse Detection** | [`data/synthetic/refresh-reuse.json`](../data/synthetic/refresh-reuse.json) | `token_refreshed` | Presented `parent_token_hash` has `is_rotated == True` in `TokenFamilyMember`. | `critical` severity. Record `TokenReuseRecord` and `AlertRecord`, reject refresh (`result: rejected`), revoke entire family. Tolerates legitimate replay of prior rotations. |
| `TL-RULE-002`<br>`(RULE-REVOKED-USE)` | **Post-Revocation Token Use** | [`data/synthetic/revoked-token.json`](../data/synthetic/revoked-token.json) | `token_used`, other actions | Presented `token_hash` has status `REVOKED` (e.g. post-logout). | `high` severity. Log detection record & alert. Accounts for out-of-order event timestamps. |
| `TL-RULE-003`<br>`(RULE-EXPIRED-USE)` | **Post-Expiration Token Use** | [`data/synthetic/expired-token.json`](../data/synthetic/expired-token.json) | `token_used`, other actions | Presented `token_hash` has status `EXPIRED` (timestamp past expiration). | `high` severity. Log detection record & alert. |
| `TL-RULE-004`<br>`(RULE-CONCURRENT-USE)` | **Concurrent Device Anomaly** | [`data/synthetic/concurrent-use.json`](../data/synthetic/concurrent-use.json) | `token_used`, `token_refreshed` | Identical `token_hash` seen across distinct `device_id` or `ip_hash` values within $\Delta t \le 60\text{s}$. | `high` severity. Emits detection record & alert. Requests from the same device and IP are permitted. |
| `TL-RULE-005`<br>`(RULE-IMPOSSIBLE-TRAVEL)`| **Impossible Travel Anomaly** | [`data/synthetic/impossible-travel.json`](../data/synthetic/impossible-travel.json) | `token_used`, `token_issued` | Consecutive events for same user/token originate from differing countries within $\Delta t \le 300\text{s}$ (5m). | `high` severity. Emits detection record & alert. |
| `TL-RULE-006` | **Normal Baseline Validation** | [`data/synthetic/normal.json`](../data/synthetic/normal.json) | All | Sequential lifecycle events match expected state machine; no reuse or velocity violations. | Confirm `accepted`, maintain lineage tree, zero false positive alerts. |

---

## 2. Detailed Rule Implementations

### TL-RULE-001: Refresh-Token Reuse Detection (`RULE-TOKEN-REUSE`)
- **Objective**: Prevent token family hijacking when an attacker obtains and replays an already-rotated refresh token.
- **Reference**: RFC 6819 Section 5.2.2.3 (Refresh Token Rotation).
- **Correlator Logic**:
  ```python
  if target_record and target_record.is_rotated:
      if event_type == "token_refreshed" and target_record.superseded_by == token_hash:
          # Legitimate replay of prior rotation - do not alert
          pass
      else:
          # True reuse anomaly
          record_alert(
              rule_id=RULE_TOKEN_REUSE,
              severity=AlertSeverity.CRITICAL.value,
              ...
          )
          # Cascade revoke entire token family
          for th in family_members:
              mark_revoked(th)
  ```

### TL-RULE-002: Use After Logout / Revocation (`RULE-REVOKED-USE`)
- **Objective**: Ensure session termination immediately invalidates all active tokens.
- **Correlator Logic**:
  When a `logout` or `token_revoked` event is ingested, the target `TokenRecord` transitions to `TokenStatus.REVOKED`. If any subsequent event presents that token hash, the correlator checks the event timestamp against the revocation timestamp. If `dt_event >= dt_rev`, a violation alert is recorded.

### TL-RULE-003: Use After Expiration (`RULE-EXPIRED-USE`)
- **Objective**: Prevent the acceptance of expired credentials.
- **Correlator Logic**:
  When a `token_expired` event is recorded, the target `TokenRecord` transitions to `TokenStatus.EXPIRED`. Subsequent usage attempts occurring after `expired_at` trigger `RULE-EXPIRED-USE`.

### TL-RULE-004: Concurrent Device Presentation (`RULE-CONCURRENT-USE`)
- **Objective**: Detect credential sharing or session sidejacking across separate machines.
- **Evaluation Criteria**:
  $$\Delta t = |t_2 - t_1| \le 60\text{s} \quad \text{and} \quad (\text{device}_1 \ne \text{device}_2 \lor \text{ip}_1 \ne \text{ip}_2)$$
  Parallel requests from the identical device and IP address are recognized as benign client concurrency.

### TL-RULE-005: Impossible Travel (`RULE-IMPOSSIBLE-TRAVEL`)
- **Objective**: Detect access from distinct geographical regions impossible within the elapsed time window.
- **Evaluation Criteria**:
  $$\Delta t = |t_2 - t_1| \le 300\text{s} \quad \text{and} \quad \text{country}_1 \ne \text{country}_2$$

---

## 3. Known Limitations & Operational Realities

1. **Risk Indicators, Not Definite Compromises**: An alert represents an anomalous behavioral pattern. Normal user behavior (VPN connections, corporate gateway switching, mobile cellular/Wi-Fi handoff) frequently produces IP or country shifts without adversary involvement.
2. **Coarse Country Resolution**: `RULE-IMPOSSIBLE-TRAVEL` evaluates country code transitions in test scenarios rather than continuous Haversine distance calculations over coordinates or ISP network routing data.
3. **Sliding Window Lifetime**: Concurrent use and travel history are tracked in the correlator's memory; restarting the process clears recent sliding-window state unless warm-started.
4. **Synthetic Test Data vs Production Defense**: Synthetic scenario tests verify the logical correctness of rules under controlled test inputs. They do not demonstrate resilience against advanced real-world adversarial evasion.
5. **Unimplemented Concepts**: Session fixation analysis and continuous risk decay scoring are conceptual research proposals, not active automated rules in `engine.py`.
