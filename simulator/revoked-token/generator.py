from typing import List, Dict, Any, Optional
from datetime import datetime
from simulator.base import BaseScenarioGenerator


class RevokedTokenScenarioGenerator(BaseScenarioGenerator):
    """
    Scenario 3: Use After Logout / Revoked Token
    Simulates a full login session, normal access, an explicit user logout /
    token revocation event, followed by an attempt to use the revoked token again.
    """

    def __init__(
        self,
        seed: Optional[int] = 42,
        base_time: Optional[datetime] = None,
        user_id: str = "user-synthetic-03",
    ):
        super().__init__(seed=seed, base_time=base_time)
        self.user_id = user_id

    def generate(self) -> List[Dict[str, Any]]:
        token_hash = self._hash(f"{self.user_id}-session-token-{self.seed}")
        token_family = f"family-logout-{self.seed}"

        user_ip_hash = self._hash(f"user-ip-office-{self.seed}")
        user_device = "device-workstation-01"

        events = []

        # 1. User logs in -> Token Issued
        events.append(self.build_event(
            event_id="evt-logout-001",
            event_type="token_issued",
            time_offset_seconds=0,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country="US",
            device_id=user_device,
            user_agent_family="Firefox",
            endpoint="/api/auth/login",
            result="accepted"
        ))

        # 2. Legitimate user uses the token
        events.append(self.build_event(
            event_id="evt-logout-002",
            event_type="token_used",
            time_offset_seconds=300,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country="US",
            device_id=user_device,
            user_agent_family="Firefox",
            endpoint="/api/v1/projects",
            result="accepted"
        ))

        # 3. User explicitly logs out / revokes session
        events.append(self.build_event(
            event_id="evt-logout-003",
            event_type="logout",
            time_offset_seconds=900,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country="US",
            device_id=user_device,
            user_agent_family="Firefox",
            endpoint="/api/auth/logout",
            result="accepted"
        ))

        # 4. Attempted use of the revoked token post-logout
        events.append(self.build_event(
            event_id="evt-logout-004",
            event_type="token_used",
            time_offset_seconds=960,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country="US",
            device_id=user_device,
            user_agent_family="Firefox",
            endpoint="/api/v1/projects",
            result="rejected"
        ))

        return events
