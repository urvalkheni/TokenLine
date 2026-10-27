from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List


class TokenStatus(str, Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REUSED = "reused"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class TokenRecord:
    token_hash: str
    token_family: str
    parent_token_hash: Optional[str] = None
    issued_at: Optional[str] = None
    rotated_at: Optional[str] = None
    expired_at: Optional[str] = None
    revoked_at: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    status: TokenStatus = TokenStatus.ACTIVE
    superseded_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_rotated(self) -> bool:
        return self.status == TokenStatus.ROTATED or self.superseded_by is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_hash": self.token_hash,
            "token_family": self.token_family,
            "parent_token_hash": self.parent_token_hash,
            "issued_at": self.issued_at,
            "rotated_at": self.rotated_at,
            "expired_at": self.expired_at,
            "revoked_at": self.revoked_at,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "status": self.status.value if isinstance(self.status, TokenStatus) else self.status,
            "superseded_by": self.superseded_by,
            "metadata": self.metadata,
        }


@dataclass
class TokenReuseRecord:
    token_hash: str
    token_family: str
    reused_at: str
    attempted_event_id: str
    detection_type: str = "refresh_reuse"
    severity: str = "critical"
    parent_token_hash: Optional[str] = None
    user_id: Optional[str] = None
    chain_context: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def detected_at(self) -> str:
        return self.reused_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_type": self.detection_type,
            "token_hash": self.token_hash,
            "token_family": self.token_family,
            "reused_at": self.reused_at,
            "detected_at": self.reused_at,
            "attempted_event_id": self.attempted_event_id,
            "severity": self.severity,
            "parent_token_hash": self.parent_token_hash,
            "user_id": self.user_id,
            "chain_context": self.chain_context,
            "metadata": self.metadata,
        }


@dataclass
class DetectionRecord:
    detection_type: str  # "refresh_reuse", "expired_token_use", "revoked_token_use", "concurrent_use", "impossible_travel"
    token_hash: str
    token_family: str
    detected_at: str
    attempted_event_id: str
    severity: str = "high"  # "critical", "high", "medium"
    parent_token_hash: Optional[str] = None
    user_id: Optional[str] = None
    chain_context: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def reused_at(self) -> str:
        """Compatibility property for consumers expecting reused_at."""
        return self.detected_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_type": self.detection_type,
            "token_hash": self.token_hash,
            "token_family": self.token_family,
            "detected_at": self.detected_at,
            "reused_at": self.detected_at,
            "attempted_event_id": self.attempted_event_id,
            "severity": self.severity,
            "parent_token_hash": self.parent_token_hash,
            "user_id": self.user_id,
            "chain_context": self.chain_context,
            "metadata": self.metadata,
        }


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Canonical Rule Identifiers
RULE_TOKEN_REUSE = "RULE-TOKEN-REUSE"
RULE_REVOKED_USE = "RULE-REVOKED-USE"
RULE_EXPIRED_USE = "RULE-EXPIRED-USE"
RULE_CONCURRENT_USE = "RULE-CONCURRENT-USE"
RULE_IMPOSSIBLE_TRAVEL = "RULE-IMPOSSIBLE-TRAVEL"

RULE_TITLES = {
    RULE_TOKEN_REUSE: "Refresh-Token Reuse Detected",
    RULE_REVOKED_USE: "Revoked-Token Use Detected",
    RULE_EXPIRED_USE: "Expired-Token Use Detected",
    RULE_CONCURRENT_USE: "Suspicious Concurrent Token Use Detected",
    RULE_IMPOSSIBLE_TRAVEL: "Impossible Travel Detected",
}

RULE_SEVERITIES = {
    RULE_TOKEN_REUSE: AlertSeverity.CRITICAL.value,
    RULE_REVOKED_USE: AlertSeverity.HIGH.value,
    RULE_EXPIRED_USE: AlertSeverity.HIGH.value,
    RULE_CONCURRENT_USE: AlertSeverity.HIGH.value,
    RULE_IMPOSSIBLE_TRAVEL: AlertSeverity.HIGH.value,
}

DETECTION_TYPE_TO_RULE = {
    "refresh_reuse": RULE_TOKEN_REUSE,
    "revoked_token_use": RULE_REVOKED_USE,
    "expired_token_use": RULE_EXPIRED_USE,
    "concurrent_use": RULE_CONCURRENT_USE,
    "impossible_travel": RULE_IMPOSSIBLE_TRAVEL,
}

RULE_TO_DETECTION_TYPE = {v: k for k, v in DETECTION_TYPE_TO_RULE.items()}


def redact_secrets(data: Any) -> Any:
    """
    Recursively scans and redacts any potential secrets, bearer tokens, or raw credentials.
    Permits only safe SHA-256 / SHA-512 hex digests and non-sensitive metadata.
    """
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            k_lower = k.lower()
            if any(term in k_lower for term in ("password", "secret", "bearer", "authorization", "private_key", "raw_token")):
                cleaned[k] = "[REDACTED_SECRET]"
            else:
                cleaned[k] = redact_secrets(v)
        return cleaned
    elif isinstance(data, list):
        return [redact_secrets(item) for item in data]
    elif isinstance(data, str):
        # Redact raw Bearer tokens if present in strings
        if data.lower().startswith("bearer "):
            return "Bearer [REDACTED_SECRET]"
        return data
    return data


@dataclass
class AlertRecord:
    id: str
    rule_id: str
    severity: str
    timestamp: str  # ISO-8601 UTC detection timestamp
    title: str
    explanation: str
    status: str = AlertStatus.OPEN.value
    event_refs: List[str] = field(default_factory=list)
    token_family_id: Optional[str] = None
    token_hash: Optional[str] = None
    user_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    dedup_fingerprint: str = ""
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def __post_init__(self):
        # Auto-populate fingerprint if missing
        if not self.dedup_fingerprint:
            ref = self.event_refs[0] if self.event_refs else "noref"
            th = self.token_hash or "nohash"
            self.dedup_fingerprint = f"{self.rule_id}:{th}:{ref}"
        if not self.title:
            self.title = RULE_TITLES.get(self.rule_id, f"Security Alert: {self.rule_id}")
        if not self.created_at:
            self.created_at = self.timestamp
        if not self.updated_at:
            self.updated_at = self.timestamp
        # Redact any secrets in evidence
        self.evidence = redact_secrets(self.evidence)

    # Polymorphic compatibility properties
    @property
    def detection_type(self) -> str:
        return RULE_TO_DETECTION_TYPE.get(self.rule_id, self.rule_id)

    @property
    def detected_at(self) -> str:
        return self.timestamp

    @property
    def reused_at(self) -> str:
        return self.timestamp

    @property
    def attempted_event_id(self) -> str:
        return self.event_refs[0] if self.event_refs else ""

    @property
    def token_family(self) -> str:
        return self.token_family_id or ""

    @property
    def metadata(self) -> Dict[str, Any]:
        return self.evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "status": self.status,
            "timestamp": self.timestamp,
            "title": self.title,
            "explanation": self.explanation,
            "event_refs": list(self.event_refs),
            "token_family_id": self.token_family_id,
            "token_hash": self.token_hash,
            "user_id": self.user_id,
            "evidence": self.evidence,
            "dedup_fingerprint": self.dedup_fingerprint,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            # Compatibility fields for legacy consumers
            "detection_type": self.detection_type,
            "detected_at": self.detected_at,
            "reused_at": self.reused_at,
            "attempted_event_id": self.attempted_event_id,
            "token_family": self.token_family,
            "metadata": self.evidence,
        }

