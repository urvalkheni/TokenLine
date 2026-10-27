"""
Standardized Labeled Incident Evaluation Datasets for TokenLine.

Provides ground-truth labeled evaluation datasets at the incident level.
Each incident consists of a coherent sequence of schema-compliant events representing
either normal benign authentication activity or a specific attack scenario.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import uuid
import hashlib

from backend.correlator.models import (
    RULE_TOKEN_REUSE,
    RULE_REVOKED_USE,
    RULE_EXPIRED_USE,
    RULE_CONCURRENT_USE,
    RULE_IMPOSSIBLE_TRAVEL,
)


@dataclass
class LabeledIncident:
    """
    Represents an incident-level evaluation case with ground-truth expectations.
    """
    case_id: str
    category: str  # "normal" or "attack"
    expected_label: str  # "normal" or "attack"
    expected_rule: Optional[str]  # e.g. RULE_TOKEN_REUSE, or None for normal
    description: str
    assumptions: str
    events: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return self.expected_label.lower() == "attack"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "expected_label": self.expected_label,
            "expected_rule": self.expected_rule,
            "description": self.description,
            "assumptions": self.assumptions,
            "event_count": len(self.events),
        }


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _make_event(
    event_type: str,
    time_iso: str,
    user_id: str,
    token_hash: str,
    token_family: str,
    parent_token_hash: Optional[str] = None,
    device_id: str = "device-1",
    ip_hash: Optional[str] = None,
    country: str = "IN",
    user_agent_family: str = "Chrome",
    endpoint: str = "/api/v1/auth/refresh",
    result: str = "accepted",
    is_simulation: bool = True,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "event_type": event_type,
        "time": time_iso,
        "user_id": user_id,
        "token_hash": token_hash,
        "token_family": token_family,
        "parent_token_hash": parent_token_hash,
        "ip_hash": ip_hash or _sha256(f"192.0.2.{user_id}"),
        "country": country,
        "device_id": device_id,
        "user_agent_family": user_agent_family,
        "endpoint": endpoint,
        "result": result,
        "schema_version": "1.0.0",
        "source": "demo-app",
        "is_simulation": is_simulation,
        "metadata": metadata or {},
    }


def get_evaluation_dataset() -> List[LabeledIncident]:
    """
    Constructs a deterministic, labeled evaluation dataset across all supported rules
    and benign baseline behaviors.
    """
    base = datetime(2026, 10, 27, 8, 0, 0, tzinfo=timezone.utc)
    incidents: List[LabeledIncident] = []

    # =========================================================================
    # 1. NORMAL (BENIGN) BASELINE INCIDENTS (Negative cases -> Expected: 0 alerts)
    # =========================================================================

    # Case 1: Clean 3-token rotation (A -> B -> C)
    fam_1 = f"family-{uuid.uuid4().hex[:8]}"
    t_a = _sha256("token-norm-1-a")
    t_b = _sha256("token-norm-1-b")
    t_c = _sha256("token-norm-1-c")
    u_1 = "user-alice"
    events_norm_1 = [
        _make_event("token_issued", (base).isoformat(), u_1, t_a, fam_1, None, endpoint="/api/v1/auth/login"),
        _make_event("token_used", (base + timedelta(seconds=30)).isoformat(), u_1, t_a, fam_1, None, endpoint="/api/v1/user/profile"),
        _make_event("token_refreshed", (base + timedelta(seconds=60)).isoformat(), u_1, t_b, fam_1, t_a, endpoint="/api/v1/auth/refresh"),
        _make_event("token_used", (base + timedelta(seconds=90)).isoformat(), u_1, t_b, fam_1, None, endpoint="/api/v1/user/profile"),
        _make_event("token_refreshed", (base + timedelta(seconds=120)).isoformat(), u_1, t_c, fam_1, t_b, endpoint="/api/v1/auth/refresh"),
    ]
    incidents.append(LabeledIncident(
        case_id="INC-NORM-001",
        category="normal",
        expected_label="normal",
        expected_rule=None,
        description="Sequential 3-step token rotation (A -> B -> C) following standard refresh semantics.",
        assumptions="Valid parent references, sequential timestamps, single device, accepted responses.",
        events=events_norm_1,
    ))

    # Case 2: Clean session lifecycle with explicit logout
    fam_2 = f"family-{uuid.uuid4().hex[:8]}"
    t_2 = _sha256("token-norm-2")
    u_2 = "user-bob"
    events_norm_2 = [
        _make_event("token_issued", (base + timedelta(seconds=10)).isoformat(), u_2, t_2, fam_2, None, endpoint="/api/v1/auth/login"),
        _make_event("token_used", (base + timedelta(seconds=40)).isoformat(), u_2, t_2, fam_2, None, endpoint="/api/v1/user/orders"),
        _make_event("logout", (base + timedelta(seconds=70)).isoformat(), u_2, t_2, fam_2, None, endpoint="/api/v1/auth/logout"),
    ]
    incidents.append(LabeledIncident(
        case_id="INC-NORM-002",
        category="normal",
        expected_label="normal",
        expected_rule=None,
        description="Standard login, resource access, and clean user logout.",
        assumptions="Session terminates cleanly, no further attempts made with revoked credentials.",
        events=events_norm_2,
    ))

    # Case 3: Benign token expiration with zero usage attempts
    fam_3 = f"family-{uuid.uuid4().hex[:8]}"
    t_3 = _sha256("token-norm-3")
    u_3 = "user-carol"
    events_norm_3 = [
        _make_event("token_issued", (base + timedelta(seconds=20)).isoformat(), u_3, t_3, fam_3, None, endpoint="/api/v1/auth/login"),
        _make_event("token_used", (base + timedelta(seconds=50)).isoformat(), u_3, t_3, fam_3, None, endpoint="/api/v1/data/feed"),
        _make_event("token_expired", (base + timedelta(seconds=3600)).isoformat(), u_3, t_3, fam_3, None, endpoint="/api/v1/cron/cleanup"),
    ]
    incidents.append(LabeledIncident(
        case_id="INC-NORM-003",
        category="normal",
        expected_label="normal",
        expected_rule=None,
        description="Normal token expiration lifecycle event with no subsequent malicious reuse.",
        assumptions="Expiration signals session expiry naturally without generating false-positive attack alerts.",
        events=events_norm_3,
    ))

    # Case 4: Legitimate parallel requests on same device/IP
    fam_4 = f"family-{uuid.uuid4().hex[:8]}"
    t_4 = _sha256("token-norm-4")
    u_4 = "user-david"
    dev_4 = "device-macbook"
    ip_4 = _sha256("198.51.100.1")
    events_norm_4 = [
        _make_event("token_issued", (base).isoformat(), u_4, t_4, fam_4, None, device_id=dev_4, ip_hash=ip_4),
        _make_event("token_used", (base + timedelta(seconds=5)).isoformat(), u_4, t_4, fam_4, None, device_id=dev_4, ip_hash=ip_4, endpoint="/api/v1/user/info"),
        _make_event("token_used", (base + timedelta(seconds=6)).isoformat(), u_4, t_4, fam_4, None, device_id=dev_4, ip_hash=ip_4, endpoint="/api/v1/user/notifications"),
    ]
    incidents.append(LabeledIncident(
        case_id="INC-NORM-004",
        category="normal",
        expected_label="normal",
        expected_rule=None,
        description="Concurrent legitimate requests from the same client session (identical device and IP).",
        assumptions="Parallel HTTP calls within 1-2 seconds on the same device do not constitute concurrent abuse.",
        events=events_norm_4,
    ))

    # Case 5: Plausible geographic travel (long time delta)
    fam_5 = f"family-{uuid.uuid4().hex[:8]}"
    t_5 = _sha256("token-norm-5")
    u_5 = "user-eva"
    events_norm_5 = [
        _make_event("token_issued", (base).isoformat(), u_5, t_5, fam_5, None, country="IN"),
        _make_event("token_used", (base + timedelta(hours=14)).isoformat(), u_5, t_5, fam_5, None, country="US"),
    ]
    incidents.append(LabeledIncident(
        case_id="INC-NORM-005",
        category="normal",
        expected_label="normal",
        expected_rule=None,
        description="Plausible intercontinental travel (India to US with a 14-hour flight window).",
        assumptions="Time difference is greater than velocity threshold (300s), representing real physical travel.",
        events=events_norm_5,
    ))

    # Case 6: Idempotent network retry of identical rotation
    fam_6 = f"family-{uuid.uuid4().hex[:8]}"
    t_6a = _sha256("token-norm-6a")
    t_6b = _sha256("token-norm-6b")
    u_6 = "user-frank"
    retry_time = (base + timedelta(seconds=100)).isoformat()
    events_norm_6 = [
        _make_event("token_issued", (base).isoformat(), u_6, t_6a, fam_6, None),
        _make_event("token_refreshed", retry_time, u_6, t_6b, fam_6, t_6a),
        _make_event("token_refreshed", retry_time, u_6, t_6b, fam_6, t_6a),  # Identical replay
    ]
    incidents.append(LabeledIncident(
        case_id="INC-NORM-006",
        category="normal",
        expected_label="normal",
        expected_rule=None,
        description="Network retry of identical rotation parameters (legitimate idempotent replay).",
        assumptions="Superseded token presenting the exact same child token hash constitutes a safe retry, not reuse.",
        events=events_norm_6,
    ))

    # =========================================================================
    # 2. ATTACK INCIDENTS (Positive cases -> Expected: 1 alert with matching rule)
    # =========================================================================

    # Case 7: Rule A - Refresh-Token Reuse Attack
    fam_atk_1 = f"family-{uuid.uuid4().hex[:8]}"
    t_atk_1a = _sha256("token-atk-1a")
    t_atk_1b = _sha256("token-atk-1b")
    t_atk_1c = _sha256("token-atk-1c-rogue")
    u_atk_1 = "user-victim-1"
    events_atk_1 = [
        _make_event("token_issued", (base).isoformat(), u_atk_1, t_atk_1a, fam_atk_1, None),
        _make_event("token_refreshed", (base + timedelta(seconds=60)).isoformat(), u_atk_1, t_atk_1b, fam_atk_1, t_atk_1a),
        # Adversary attempts to refresh using rotated Token A to obtain Token C
        _make_event("token_refreshed", (base + timedelta(seconds=120)).isoformat(), u_atk_1, t_atk_1c, fam_atk_1, t_atk_1a, device_id="attacker-box", result="rejected"),
    ]
    incidents.append(LabeledIncident(
        case_id="INC-ATK-REUSE-001",
        category="attack",
        expected_label="attack",
        expected_rule=RULE_TOKEN_REUSE,
        description="Adversary attempts to use a previously rotated refresh token to obtain a new token.",
        assumptions="Parent token was already rotated to a different child hash, indicating credential theft/replay.",
        events=events_atk_1,
    ))

    # Case 8: Rule B - Revoked-Token Use Attack
    fam_atk_2 = f"family-{uuid.uuid4().hex[:8]}"
    t_atk_2 = _sha256("token-atk-2")
    u_atk_2 = "user-victim-2"
    events_atk_2 = [
        _make_event("token_issued", (base).isoformat(), u_atk_2, t_atk_2, fam_atk_2, None),
        _make_event("logout", (base + timedelta(seconds=30)).isoformat(), u_atk_2, t_atk_2, fam_atk_2, None),
        # Adversary attempts to use the revoked token after logout (outside concurrent 60s window)
        _make_event("token_used", (base + timedelta(seconds=120)).isoformat(), u_atk_2, t_atk_2, fam_atk_2, None, device_id="attacker-laptop", result="rejected"),
    ]
    incidents.append(LabeledIncident(
        case_id="INC-ATK-REVOKED-001",
        category="attack",
        expected_label="attack",
        expected_rule=RULE_REVOKED_USE,
        description="Adversary presents a token whose family or status was explicitly revoked via user logout.",
        assumptions="Attempted usage strictly succeeds the revocation timestamp.",
        events=events_atk_2,
    ))

    # Case 9: Rule C - Expired-Token Use Attack
    fam_atk_3 = f"family-{uuid.uuid4().hex[:8]}"
    t_atk_3 = _sha256("token-atk-3")
    u_atk_3 = "user-victim-3"
    events_atk_3 = [
        _make_event("token_issued", (base).isoformat(), u_atk_3, t_atk_3, fam_atk_3, None),
        _make_event("token_expired", (base + timedelta(seconds=300)).isoformat(), u_atk_3, t_atk_3, fam_atk_3, None),
        # Adversary attempts to access protected resource with expired token
        _make_event("token_used", (base + timedelta(seconds=350)).isoformat(), u_atk_3, t_atk_3, fam_atk_3, None, result="rejected"),
    ]
    incidents.append(LabeledIncident(
        case_id="INC-ATK-EXPIRED-001",
        category="attack",
        expected_label="attack",
        expected_rule=RULE_EXPIRED_USE,
        description="Client or adversary presents a token for resource access after its explicit expiration time.",
        assumptions="Attempted usage strictly succeeds the expiration timestamp.",
        events=events_atk_3,
    ))

    # Case 10: Rule D - Concurrent Token Use Attack
    fam_atk_4 = f"family-{uuid.uuid4().hex[:8]}"
    t_atk_4 = _sha256("token-atk-4")
    u_atk_4 = "user-victim-4"
    events_atk_4 = [
        _make_event("token_issued", (base).isoformat(), u_atk_4, t_atk_4, fam_atk_4, None, device_id="victim-iphone", ip_hash=_sha256("10.0.0.1")),
        _make_event("token_used", (base + timedelta(seconds=10)).isoformat(), u_atk_4, t_atk_4, fam_atk_4, None, device_id="victim-iphone", ip_hash=_sha256("10.0.0.1")),
        # Overlapping usage from completely different device and IP within 15 seconds
        _make_event("token_used", (base + timedelta(seconds=25)).isoformat(), u_atk_4, t_atk_4, fam_atk_4, None, device_id="attacker-rig", ip_hash=_sha256("203.0.113.99"), result="rejected"),
    ]
    incidents.append(LabeledIncident(
        case_id="INC-ATK-CONCURRENT-001",
        category="attack",
        expected_label="attack",
        expected_rule=RULE_CONCURRENT_USE,
        description="Simultaneous token usage from distinct device IDs and IP hashes within 60 seconds.",
        assumptions="Indicates token exfiltration and concurrent adversary session.",
        events=events_atk_4,
    ))

    # Case 11: Rule E - Impossible Travel Attack
    fam_atk_5 = f"family-{uuid.uuid4().hex[:8]}"
    t_atk_5 = _sha256("token-atk-5")
    u_atk_5 = "user-victim-5"
    events_atk_5 = [
        _make_event("token_issued", (base).isoformat(), u_atk_5, t_atk_5, fam_atk_5, None, country="IN"),
        _make_event("token_used", (base + timedelta(seconds=10)).isoformat(), u_atk_5, t_atk_5, fam_atk_5, None, country="IN"),
        # Intercontinental switch (India -> US) within 120 seconds
        _make_event("token_used", (base + timedelta(seconds=130)).isoformat(), u_atk_5, t_atk_5, fam_atk_5, None, country="US", result="rejected"),
    ]
    incidents.append(LabeledIncident(
        case_id="INC-ATK-TRAVEL-001",
        category="attack",
        expected_label="attack",
        expected_rule=RULE_IMPOSSIBLE_TRAVEL,
        description="Authentication from India followed by United States within 120 seconds (<= 300s window).",
        assumptions="Exceeds plausible physical travel speed (> 100,000 km/h), indicating proxy/stolen credential use.",
        events=events_atk_5,
    ))

    return incidents
