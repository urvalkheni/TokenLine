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

