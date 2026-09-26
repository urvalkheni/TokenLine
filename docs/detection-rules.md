# TokenLine Detection Rules & Anomaly Signatures

This document defines the core detection rules implemented and verified against the synthetic token lifecycle datasets.

---

## Detection Rule Matrix

| Rule ID | Rule Name | Target Dataset | Input Event Type | Condition & Logic | Emitted Signal / Action |
|---|---|---|---|---|---|
| `TL-RULE-001` | **Refresh-Token Reuse Detection** | [`refresh-reuse.json`](file:///d:/TokenLine/TokenLine/data/synthetic/refresh-reuse.json) | `token_refreshed` | Presented `parent_token_hash` has `is_rotated == True` in `TokenFamilyMember`. | Record `TokenReuseRecord`, reject refresh (`result: rejected`), revoke family. |
| `TL-RULE-002` | **Post-Revocation Token Use** | [`revoked-token.json`](file:///d:/TokenLine/TokenLine/data/synthetic/revoked-token.json) | `token_used` | Presented `token_hash` has status `REVOKED` or followed a `logout` event. | Deny access (`result: rejected`), trigger unauthorized access audit alert. |
| `TL-RULE-003` | **Post-Expiration Token Use** | [`expired-token.json`](file:///d:/TokenLine/TokenLine/data/synthetic/expired-token.json) | `token_used` | Presented `token_hash` has status `EXPIRED` or timestamp exceeds issuance + TTL. | Deny access (`result: rejected`), force re-authentication. |
| `TL-RULE-004` | **Concurrent Device Anomaly** | [`concurrent-use.json`](file:///d:/TokenLine/TokenLine/data/synthetic/concurrent-use.json) | `token_used` | Identical `token_hash` seen across distinct `device_id` values within threshold $\Delta t \le 60\text{s}$. | Log `suspicious_device` event, flag session for step-up authentication. |
| `TL-RULE-005` | **Impossible Travel Velocity** | [`impossible-travel.json`](file:///d:/TokenLine/TokenLine/data/synthetic/impossible-travel.json) | `token_used` / `token_issued` | Consecutive events for same token have distance/time velocity $v > 900\text{ km/h}$. | Log `suspicious_location` event, challenge user with MFA, terminate token. |
| `TL-RULE-006` | **Normal Baseline Validation** | [`normal.json`](file:///d:/TokenLine/TokenLine/data/synthetic/normal.json) | All | Sequential lifecycle events match expected state machine; no reuse or velocity violations. | Confirm `accepted`, maintain lineage tree, zero false positive alerts. |

---

## Detailed Rule Explanations

### TL-RULE-001: Refresh-Token Reuse Detection
- **Objective**: Prevent token family hijacking when an attacker obtains an already-rotated refresh token.
- **Reference**: RFC 6819 Section 5.2.2.3 (Refresh Token Rotation).
- **Correlator Implementation**:
  ```python
  existing = db.query(TokenFamilyMember).filter(TokenFamilyMember.token_hash == parent_token_hash).first()
  if existing and existing.is_rotated:
      # Flag reuse violation
      reuse_record = TokenReuseRecord(
          token_hash=parent_token_hash,
          token_family=existing.token_family,
          reused_at=time,
          attempted_event_id=event_id
      )
  ```

### TL-RULE-002: Use After Logout / Revocation
- **Objective**: Ensure session termination immediately invalidates all active tokens.
- **Correlator Implementation**:
  When a `logout` or `token_revoked` event is ingested, the target `TokenRecord` is updated to `TokenStatus.REVOKED`. Any subsequent `token_used` event for that hash is rejected.

### TL-RULE-003: Use After Expiration
- **Objective**: Prevent the acceptance of stale credentials.
- **Correlator Implementation**:
  When a `token_expired` event is recorded, the target `TokenRecord` transitions to `TokenStatus.EXPIRED`. Subsequent usage attempts result in `result: rejected`.

### TL-RULE-004: Concurrent Device Presentation
- **Objective**: Detect credential sharing or session sidejacking.
- **Evaluation Criteria**:
  $$\Delta t = |t_2 - t_1| \le \text{Threshold (e.g. 60s)} \quad \text{and} \quad \text{device}_1 \ne \text{device}_2$$
- If satisfied, the collector or detection engine emits `suspicious_device`.

### TL-RULE-005: Impossible Travel Velocity
- **Objective**: Detect access from distinct geographical regions impossible within the elapsed time window.
- **Evaluation Criteria**:
  $$v = \frac{\text{haversine}(\text{coord}_1, \text{coord}_2)}{\Delta t} > 900\text{ km/h}$$
  In synthetic test datasets:
  - Location 1: India (`IN`)
  - Location 2: United States (`US`)
  - Time interval: 240 seconds ($\approx 180,000\text{ km/h}$)
  - Triggers `suspicious_location` rejection.
