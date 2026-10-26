import pytest
from datetime import datetime, timezone
from backend.correlator import (
    TokenFamilyCorrelator,
    TokenStatus,
    TokenRecord,
    TokenReuseRecord,
    DetectionRecord,
    process_event,
    get_detection_records,
)


@pytest.fixture
def correlator():
    c = TokenFamilyCorrelator()
    c.clear()
    return c


# ==============================================================================
# 1. NORMAL VS SUSPICIOUS EXPIRATION
# ==============================================================================

def test_normal_expiration_produces_no_alerts(correlator):
    """
    Legitimate token expiration naturally occurring at end of TTL must update state
    to EXPIRED, return None, and generate zero false-positive attack alerts.
    """
    token_hash = "11111111111111111111111111111111"
    family_id = "fam-exp-01"

    # 1. Issue token
    correlator.process_event({
        "event_id": "evt-iss-01",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "user-01",
        "token_hash": token_hash,
        "token_family": family_id,
        "ip_hash": "ip-user-01",
        "device_id": "dev-01",
        "result": "accepted",
    })
    assert correlator.tokens[token_hash].status == TokenStatus.ACTIVE

    # 2. Normal expiration event arrives
    res = correlator.process_event({
        "event_id": "evt-exp-01",
        "event_type": "token_expired",
        "time": "2026-09-01T11:00:00Z",
        "user_id": "user-01",
        "token_hash": token_hash,
        "token_family": family_id,
        "ip_hash": "ip-user-01",
        "device_id": "dev-01",
        "result": "accepted",
    })

    # Benign lifecycle event: returns None, token is EXPIRED, zero alerts
    assert res is None
    assert correlator.tokens[token_hash].status == TokenStatus.EXPIRED
    assert correlator.tokens[token_hash].expired_at == "2026-09-01T11:00:00Z"
    assert len(correlator.get_detection_records()) == 0

    # 3. Duplicate expiration event is idempotent
    res_dup = correlator.process_event({
        "event_id": "evt-exp-01-retry",
        "event_type": "token_expired",
        "time": "2026-09-01T11:00:00Z",
        "user_id": "user-01",
        "token_hash": token_hash,
        "token_family": family_id,
        "ip_hash": "ip-user-01",
        "device_id": "dev-01",
        "result": "accepted",
    })
    assert res_dup is None
    assert correlator.tokens[token_hash].status == TokenStatus.EXPIRED
    assert len(correlator.get_detection_records()) == 0


def test_use_before_expiration_accepted_no_alerts(correlator):
    """
    An out-of-order usage event that legitimately occurred before the token expired
    must NOT be flagged as an expired-token use attack.
    """
    token_hash = "22222222222222222222222222222222"
    family_id = "fam-exp-02"

    correlator.process_event({
        "event_id": "evt-iss-02",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "user-02",
        "token_hash": token_hash,
        "token_family": family_id,
        "ip_hash": "ip-user-02",
        "device_id": "dev-02",
        "result": "accepted",
    })

    # Expiration recorded at 11:00:00Z
    correlator.process_event({
        "event_id": "evt-exp-02",
        "event_type": "token_expired",
        "time": "2026-09-01T11:00:00Z",
        "user_id": "user-02",
        "token_hash": token_hash,
        "token_family": family_id,
        "ip_hash": "ip-user-02",
        "device_id": "dev-02",
        "result": "accepted",
    })

    # Delayed event from 10:45:00Z (strictly prior to 11:00:00Z)
    res = correlator.process_event({
        "event_id": "evt-delayed-use",
        "event_type": "token_used",
        "time": "2026-09-01T10:45:00Z",
        "user_id": "user-02",
        "token_hash": token_hash,
        "token_family": family_id,
        "ip_hash": "ip-user-02",
        "device_id": "dev-02",
        "result": "accepted",
    })

    assert res is None
    assert len(correlator.get_detection_records()) == 0


def test_use_at_or_after_expiration_triggers_alert(correlator):
    """
    Attempting to authenticate, refresh, or use a token at or after its expiration
    timestamp must trigger an expired_token_use attack alert.
    """
    token_hash = "33333333333333333333333333333333"
    family_id = "fam-exp-03"

    correlator.process_event({
        "event_id": "evt-iss-03",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "user-03",
        "token_hash": token_hash,
        "token_family": family_id,
        "ip_hash": "ip-03",
        "device_id": "dev-03",
        "result": "accepted",
    })
    correlator.process_event({
        "event_id": "evt-exp-03",
        "event_type": "token_expired",
        "time": "2026-09-01T11:00:00Z",
        "user_id": "user-03",
        "token_hash": token_hash,
        "token_family": family_id,
        "ip_hash": "ip-03",
        "device_id": "dev-03",
        "result": "accepted",
    })

    # Attempted use 5 minutes after expiration
    det = correlator.process_event({
        "event_id": "evt-attack-expired-use",
        "event_type": "token_used",
        "time": "2026-09-01T11:05:00Z",
        "user_id": "user-03",
        "token_hash": token_hash,
        "token_family": family_id,
        "ip_hash": "ip-03",
        "device_id": "dev-03",
        "result": "rejected",
    })

    assert det is not None
    assert det.detection_type == "expired_token_use"
    assert det.token_hash == token_hash
    assert det.severity == "high"
    assert det.attempted_event_id == "evt-attack-expired-use"

    records = correlator.get_detection_records(detection_type="expired_token_use")
    assert len(records) == 1
    assert records[0].token_hash == token_hash


# ==============================================================================
# 2. TOKEN-LEVEL VS FAMILY-LEVEL REVOCATION
# ==============================================================================

def test_token_level_revocation_scope(correlator):
    """
    Token-level revocation revokes only the specific token; sibling and child
    tokens in the family remain ACTIVE and valid for use.
    """
    tok_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    tok_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    tok_c = "cccccccccccccccccccccccccccccccc"
    family_id = "fam-rev-scope"

    # Build chain A -> B -> C
    correlator.process_event({
        "event_id": "e-iss-a",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "user-rev",
        "token_hash": tok_a,
        "token_family": family_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })
    correlator.process_event({
        "event_id": "e-ref-b",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:10:00Z",
        "user_id": "user-rev",
        "token_hash": tok_b,
        "parent_token_hash": tok_a,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })
    correlator.process_event({
        "event_id": "e-ref-c",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:20:00Z",
        "user_id": "user-rev",
        "token_hash": tok_c,
        "parent_token_hash": tok_b,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    assert correlator.tokens[tok_c].status == TokenStatus.ACTIVE

    # Revoke ONLY Token B (explicit token-level scope)
    correlator.process_event({
        "event_id": "e-rev-b",
        "event_type": "token_revoked",
        "time": "2026-09-01T10:25:00Z",
        "user_id": "user-rev",
        "token_hash": tok_b,
        "token_family": family_id,
        "revocation_scope": "token",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    assert correlator.tokens[tok_b].status == TokenStatus.REVOKED
    # Token C must remain ACTIVE
    assert correlator.tokens[tok_c].status == TokenStatus.ACTIVE

    # Using Token C succeeds with zero alerts
    res_c = correlator.process_event({
        "event_id": "e-use-c",
        "event_type": "token_used",
        "time": "2026-09-01T10:30:00Z",
        "user_id": "user-rev",
        "token_hash": tok_c,
        "token_family": family_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })
    assert res_c is None
    assert len(correlator.get_detection_records()) == 0

    # Using revoked Token B triggers revoked_token_use detection
    det_b = correlator.process_event({
        "event_id": "e-use-b-attack",
        "event_type": "token_used",
        "time": "2026-09-01T10:35:00Z",
        "user_id": "user-rev",
        "token_hash": tok_b,
        "token_family": family_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "rejected",
    })
    assert det_b is not None
    assert det_b.detection_type == "revoked_token_use"
    assert det_b.token_hash == tok_b


def test_family_level_revocation_on_logout(correlator):
    """
    Explicit user logout triggers family-level revocation, invalidating all tokens
    in the family so any subsequent use of any member is flagged.
    """
    tok_1 = "12121212121212121212121212121212"
    tok_2 = "23232323232323232323232323232323"
    family_id = "fam-logout-all"

    correlator.process_event({
        "event_id": "e-iss-1",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-logout",
        "token_hash": tok_1,
        "token_family": family_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })
    correlator.process_event({
        "event_id": "e-ref-2",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:10:00Z",
        "user_id": "u-logout",
        "token_hash": tok_2,
        "parent_token_hash": tok_1,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    # Explicit user logout
    correlator.process_event({
        "event_id": "e-logout",
        "event_type": "logout",
        "time": "2026-09-01T10:20:00Z",
        "user_id": "u-logout",
        "token_hash": tok_2,
        "token_family": family_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    # Both tokens in family must now be REVOKED
    assert correlator.tokens[tok_1].status == TokenStatus.REVOKED
    assert correlator.tokens[tok_2].status == TokenStatus.REVOKED

    # Attempting to use Token 2 post-logout triggers revoked_token_use
    det = correlator.process_event({
        "event_id": "e-attack-post-logout",
        "event_type": "token_used",
        "time": "2026-09-01T10:25:00Z",
        "user_id": "u-logout",
        "token_hash": tok_2,
        "token_family": family_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "rejected",
    })
    assert det is not None
    assert det.detection_type == "revoked_token_use"
    assert det.token_hash == tok_2


# ==============================================================================
# 3. CONCURRENT-USE DETECTION (SUSPICIOUS VS LEGITIMATE PARALLEL)
# ==============================================================================

def test_concurrent_use_distinct_devices_detected(correlator):
    """
    Presenting the same token from distinct devices or IPs within 60 seconds
    must be flagged as concurrent_use.
    """
    tok = "44444444444444444444444444444444"
    fam = "fam-concurrent"

    # Token issued
    correlator.process_event({
        "event_id": "e-iss-c",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-concur",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-office",
        "device_id": "dev-workstation",
        "result": "accepted",
    })

    # Legitimate usage from Workstation
    correlator.process_event({
        "event_id": "e-use-legit",
        "event_type": "token_used",
        "time": "2026-09-01T10:01:00Z",
        "user_id": "u-concur",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-office",
        "device_id": "dev-workstation",
        "result": "accepted",
    })

    # Overlapping use 15 seconds later from a different device & IP
    det = correlator.process_event({
        "event_id": "e-use-concurrent-attacker",
        "event_type": "token_used",
        "time": "2026-09-01T10:01:15Z",
        "user_id": "u-concur",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-attacker",
        "device_id": "dev-attacker-phone",
        "result": "accepted",
    })

    assert det is not None
    assert det.detection_type == "concurrent_use"
    assert det.token_hash == tok
    assert det.severity == "high"
    assert det.metadata["prior_device"] == "dev-workstation"
    assert det.metadata["current_device"] == "dev-attacker-phone"


def test_concurrent_use_legitimate_parallel_requests_no_alert(correlator):
    """
    Legitimate parallel requests from the same client session (same device_id AND
    same ip_hash within 60s) must NOT trigger concurrent use false positives.
    """
    tok = "55555555555555555555555555555555"
    fam = "fam-parallel"

    correlator.process_event({
        "event_id": "e-iss-p",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-parallel",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-home-fiber",
        "device_id": "dev-macbook-pro",
        "result": "accepted",
    })

    # Three simultaneous API requests fired in parallel by browser tabs
    r1 = correlator.process_event({
        "event_id": "e-parallel-req-1",
        "event_type": "token_used",
        "time": "2026-09-01T10:00:01Z",
        "user_id": "u-parallel",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-home-fiber",
        "device_id": "dev-macbook-pro",
        "result": "accepted",
    })
    r2 = correlator.process_event({
        "event_id": "e-parallel-req-2",
        "event_type": "token_used",
        "time": "2026-09-01T10:00:02Z",
        "user_id": "u-parallel",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-home-fiber",
        "device_id": "dev-macbook-pro",
        "result": "accepted",
    })
    r3 = correlator.process_event({
        "event_id": "e-parallel-req-3",
        "event_type": "token_used",
        "time": "2026-09-01T10:00:03Z",
        "user_id": "u-parallel",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-home-fiber",
        "device_id": "dev-macbook-pro",
        "result": "accepted",
    })

    assert r1 is None
    assert r2 is None
    assert r3 is None
    assert len(correlator.get_detection_records()) == 0


# ==============================================================================
# 4. IMPOSSIBLE-TRAVEL DETECTION (IMPOSSIBLE VS PLAUSIBLE TRAVEL)
# ==============================================================================

def test_impossible_travel_intercontinental_detected(correlator):
    """
    Sequential events across different countries within <= 300 seconds (5 minutes)
    must trigger an impossible_travel detection alert.
    """
    tok = "66666666666666666666666666666666"
    fam = "fam-travel-01"

    # Activity in Mumbai, India
    correlator.process_event({
        "event_id": "e-travel-mumbai",
        "event_type": "token_issued",
        "time": "2026-09-01T12:00:00Z",
        "user_id": "u-traveler",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-in",
        "country": "IN",
        "device_id": "dev-laptop",
        "result": "accepted",
    })

    # Activity 2 minutes later in New York, USA
    det = correlator.process_event({
        "event_id": "e-travel-ny",
        "event_type": "token_used",
        "time": "2026-09-01T12:02:00Z",
        "user_id": "u-traveler",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-us",
        "country": "US",
        "device_id": "dev-laptop",
        "result": "accepted",
    })

    assert det is not None
    assert det.detection_type == "impossible_travel"
    assert det.severity == "high"
    assert det.metadata["origin_country"] == "IN"
    assert det.metadata["dest_country"] == "US"
    assert det.metadata["time_delta_seconds"] == 120.0


def test_impossible_travel_negative_cases(correlator):
    """
    Ordinary travel (> 300s), same country, or missing location data must NOT
    trigger false positive impossible travel alerts.
    """
    tok = "77777777777777777777777777777777"
    fam = "fam-travel-neg"

    # 1. Same country sequential use: no alert
    correlator.process_event({
        "event_id": "e-same-1",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-local",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-us-1",
        "country": "US",
        "device_id": "dev",
        "result": "accepted",
    })
    r_same = correlator.process_event({
        "event_id": "e-same-2",
        "event_type": "token_used",
        "time": "2026-09-01T10:02:00Z",
        "user_id": "u-local",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip-us-1",
        "country": "US",
        "device_id": "dev",
        "result": "accepted",
    })
    assert r_same is None
    assert len(correlator.get_detection_records(detection_type="impossible_travel")) == 0

    # 2. Missing location: cannot prove impossible travel
    tok_no_geo = "88888888888888888888888888888888"
    correlator.process_event({
        "event_id": "e-nogeo-1",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-nogeo",
        "token_hash": tok_no_geo,
        "token_family": "fam-nogeo",
        "ip_hash": "ip-1",
        "country": None,
        "device_id": "dev",
        "result": "accepted",
    })
    r_nogeo = correlator.process_event({
        "event_id": "e-nogeo-2",
        "event_type": "token_used",
        "time": "2026-09-01T10:01:00Z",
        "user_id": "u-nogeo",
        "token_hash": tok_no_geo,
        "token_family": "fam-nogeo",
        "ip_hash": "ip-1",
        "country": "FR",
        "device_id": "dev",
        "result": "accepted",
    })
    assert r_nogeo is None
    assert len(correlator.get_detection_records(detection_type="impossible_travel")) == 0

    # 3. Plausible travel interval (8 hours apart across countries)
    tok_flight = "99999999999999999999999999999999"
    correlator.process_event({
        "event_id": "e-flight-1",
        "event_type": "token_issued",
        "time": "2026-09-01T08:00:00Z",
        "user_id": "u-flight",
        "token_hash": tok_flight,
        "token_family": "fam-flight",
        "ip_hash": "ip-uk",
        "country": "GB",
        "device_id": "dev",
        "result": "accepted",
    })
    r_flight = correlator.process_event({
        "event_id": "e-flight-2",
        "event_type": "token_used",
        "time": "2026-09-01T16:00:00Z",
        "user_id": "u-flight",
        "token_hash": tok_flight,
        "token_family": "fam-flight",
        "ip_hash": "ip-us",
        "country": "US",
        "device_id": "dev",
        "result": "accepted",
    })
    assert r_flight is None
    assert len(correlator.get_detection_records(detection_type="impossible_travel")) == 0


# ==============================================================================
# 5. OUT-OF-ORDER RECONCILIATION & DEDUPLICATION
# ==============================================================================

def test_out_of_order_rotation_before_issuance(correlator):
    """
    When token_refreshed arrives before token_issued of parent, the parent
    must be provisionally registered as ROTATED and maintain that status
    when token_issued arrives later.
    """
    tok_parent = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01"
    tok_child = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb02"
    fam_id = "fam-ooo-01"

    # Step 1: token_refreshed arrives first
    correlator.process_event({
        "event_id": "e-ooo-refresh",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:10:00Z",
        "user_id": "u-ooo",
        "token_hash": tok_child,
        "parent_token_hash": tok_parent,
        "token_family": fam_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    assert correlator.tokens[tok_parent].status == TokenStatus.ROTATED
    assert correlator.tokens[tok_child].status == TokenStatus.ACTIVE

    # Step 2: Delayed token_issued for parent arrives later
    correlator.process_event({
        "event_id": "e-ooo-parent-issue",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-ooo",
        "token_hash": tok_parent,
        "token_family": fam_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    # Parent MUST remain ROTATED, NOT overwritten by ACTIVE!
    assert correlator.tokens[tok_parent].status == TokenStatus.ROTATED
    assert correlator.tokens[tok_parent].superseded_by == tok_child

    # Reconstruct chain from either node
    assert correlator.reconstruct_chain(tok_parent) == [tok_parent, tok_child]
    assert correlator.reconstruct_chain(tok_child) == [tok_parent, tok_child]


def test_duplicate_detection_evidence_deduplicated(correlator):
    """
    Duplicate submissions of attack evidence (e.g. replaying the same attack event)
    must NOT generate duplicate alert records.
    """
    tok_parent = "parent11111111111111111111111111"
    tok_child = "child222222222222222222222222222"
    fam_id = "fam-dedup"

    # Issue parent and rotate to child
    correlator.process_event({
        "event_id": "e-iss",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-dedup",
        "token_hash": tok_parent,
        "token_family": fam_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })
    correlator.process_event({
        "event_id": "e-rot",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:05:00Z",
        "user_id": "u-dedup",
        "token_hash": tok_child,
        "parent_token_hash": tok_parent,
        "token_family": fam_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    attack_event = {
        "event_id": "e-attack-reuse-evidence",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:10:00Z",
        "user_id": "u-attacker",
        "token_hash": "attackerchild3333333333333333333",
        "parent_token_hash": tok_parent,
        "token_family": fam_id,
        "ip_hash": "ip-att",
        "device_id": "dev-att",
        "result": "rejected",
    }

    # First presentation flags reuse
    det1 = correlator.process_event(attack_event)
    assert det1 is not None

    # Replay of exact same attack event evidence
    det2 = correlator.process_event(attack_event)
    assert det2 is not None

    # Verify alerts list contains exactly ONE record (no duplicates)
    reuse_records = correlator.get_reuse_records(token_hash=tok_parent)
    assert len(reuse_records) == 1

    detection_records = correlator.get_detection_records(detection_type="refresh_reuse", token_hash=tok_parent)
    assert len(detection_records) == 1


# ==============================================================================
# 6. EDGE CASES: BOUNDARIES, REFRESH ATTEMPTS ON TERMINAL TOKENS, & ROLLBACK
# ==============================================================================

def test_refresh_expired_parent_token_triggers_alert(correlator):
    """
    Attempting to exchange an expired parent token via token_refreshed must trigger
    an expired_token_use detection alert.
    """
    parent_tok = "parent_exp_11111111111111111111"
    child_tok = "child_exp_222222222222222222222"
    fam_id = "fam-exp-refresh"

    # Issue parent
    correlator.process_event({
        "event_id": "e-p-iss",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-exp-ref",
        "token_hash": parent_tok,
        "token_family": fam_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })
    # Expire parent
    correlator.process_event({
        "event_id": "e-p-exp",
        "event_type": "token_expired",
        "time": "2026-09-01T11:00:00Z",
        "user_id": "u-exp-ref",
        "token_hash": parent_tok,
        "token_family": fam_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    # Attempt refresh presenting expired parent
    det = correlator.process_event({
        "event_id": "e-attack-refresh-expired",
        "event_type": "token_refreshed",
        "time": "2026-09-01T11:05:00Z",
        "user_id": "u-exp-ref",
        "token_hash": child_tok,
        "parent_token_hash": parent_tok,
        "token_family": fam_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "rejected",
    })

    assert det is not None
    assert det.detection_type == "expired_token_use"
    assert det.token_hash == parent_tok


def test_refresh_revoked_parent_token_triggers_alert(correlator):
    """
    Attempting to exchange a revoked parent token via token_refreshed must trigger
    a revoked_token_use detection alert.
    """
    parent_tok = "parent_rev_11111111111111111111"
    child_tok = "child_rev_222222222222222222222"
    fam_id = "fam-rev-refresh"

    correlator.process_event({
        "event_id": "e-pr-iss",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-rev-ref",
        "token_hash": parent_tok,
        "token_family": fam_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })
    correlator.process_event({
        "event_id": "e-pr-rev",
        "event_type": "token_revoked",
        "time": "2026-09-01T10:15:00Z",
        "user_id": "u-rev-ref",
        "token_hash": parent_tok,
        "token_family": fam_id,
        "revocation_scope": "token",
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    # Attempt refresh presenting revoked parent
    det = correlator.process_event({
        "event_id": "e-attack-refresh-revoked",
        "event_type": "token_refreshed",
        "time": "2026-09-01T10:20:00Z",
        "user_id": "u-rev-ref",
        "token_hash": child_tok,
        "parent_token_hash": parent_tok,
        "token_family": fam_id,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "rejected",
    })

    assert det is not None
    assert det.detection_type == "revoked_token_use"
    assert det.token_hash == parent_tok


def test_exact_timestamp_boundary_expiration(correlator):
    """
    A token used at the exact timestamp of expiration (T_event == T_expired)
    has elapsed its valid lifetime and must trigger an expired_token_use alert.
    """
    tok = "boundary111111111111111111111111"
    fam = "fam-boundary"

    correlator.process_event({
        "event_id": "e-b-iss",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-bound",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })
    correlator.process_event({
        "event_id": "e-b-exp",
        "event_type": "token_expired",
        "time": "2026-09-01T11:00:00Z",
        "user_id": "u-bound",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    # Used at the exact boundary timestamp
    det = correlator.process_event({
        "event_id": "e-b-use-exact",
        "event_type": "token_used",
        "time": "2026-09-01T11:00:00Z",
        "user_id": "u-bound",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "rejected",
    })

    assert det is not None
    assert det.detection_type == "expired_token_use"


def test_transaction_rollback_reverts_state_and_detections(correlator):
    """
    When an error occurs during a transaction, all in-memory changes (tokens,
    detection records, usages) must be cleanly rolled back to context entry.
    """
    tok = "rollback111111111111111111111111"
    fam = "fam-rb"

    correlator.process_event({
        "event_id": "e-rb-iss",
        "event_type": "token_issued",
        "time": "2026-09-01T10:00:00Z",
        "user_id": "u-rb",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })
    correlator.process_event({
        "event_id": "e-rb-exp",
        "event_type": "token_expired",
        "time": "2026-09-01T11:00:00Z",
        "user_id": "u-rb",
        "token_hash": tok,
        "token_family": fam,
        "ip_hash": "ip",
        "device_id": "dev",
        "result": "accepted",
    })

    assert len(correlator.get_detection_records()) == 0

    with pytest.raises(RuntimeError):
        with correlator.transaction():
            correlator.process_event({
                "event_id": "e-rb-fail",
                "event_type": "token_used",
                "time": "2026-09-01T11:05:00Z",
                "user_id": "u-rb",
                "token_hash": tok,
                "token_family": fam,
                "ip_hash": "ip",
                "device_id": "dev",
                "result": "rejected",
            })
            # Verify detection existed inside transaction
            assert len(correlator.get_detection_records()) == 1
            raise RuntimeError("Simulated transaction failure")

    # Outside transaction after rollback: detection record must be cleanly rolled back
    assert len(correlator.get_detection_records()) == 0
