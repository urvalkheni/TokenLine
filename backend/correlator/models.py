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
    parent_token_hash: Optional[str] = None
    user_id: Optional[str] = None
    chain_context: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_hash": self.token_hash,
            "token_family": self.token_family,
            "reused_at": self.reused_at,
            "attempted_event_id": self.attempted_event_id,
            "parent_token_hash": self.parent_token_hash,
            "user_id": self.user_id,
            "chain_context": self.chain_context,
            "metadata": self.metadata,
        }
