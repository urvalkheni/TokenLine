from typing import List, Dict, Any, Optional
from datetime import datetime
from simulator.base import BaseScenarioGenerator


class NormalScenarioGenerator(BaseScenarioGenerator):
    """
    Scenario: Normal Token Lifecycle
    Simulates a standard authentication and token lifecycle without any attacks or anomalies:
    1. Initial authentication and token issuance.
    2. Legitimate token usage across API endpoints.
    3. Standard token refresh and rotation (Token A -> Token B).
    4. Legitimate usage of the new rotated token.
    5. Clean user logout terminating the session.
    All events are accepted with strictly ordered timestamps and consistent family correlation.
    """

    def __init__(
        self,
        seed: Optional[int] = 42,
        base_time: Optional[datetime] = None,
        user_id: str = "user-synthetic-normal",
    ):
        super().__init__(seed=seed, base_time=base_time)
        self.user_id = user_id

    def generate(self) -> List[Dict[str, Any]]:
        token_hash_a = self._hash(f"{self.user_id}-token-alpha-{self.seed}")
        token_hash_b = self._hash(f"{self.user_id}-token-beta-{self.seed}")
        token_family = f"family-normal-{self.seed}"

        user_ip_hash = self._hash(f"legit-ip-workstation-{self.seed}")
        user_device = "device-workstation-normal"
        user_agent = "Chrome"
        country = "US"

        events = []

        # 1. User logs in -> Token A issued
        events.append(self.build_event(
            event_id="evt-normal-001",
            event_type="token_issued",
            time_offset_seconds=0,
            user_id=self.user_id,
            token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country=country,
            device_id=user_device,
            user_agent_family=user_agent,
            endpoint="/api/auth/login",
            result="accepted",
        ))

        # 2. Legitimate user accesses user profile
        events.append(self.build_event(
            event_id="evt-normal-002",
            event_type="token_used",
            time_offset_seconds=120,
            user_id=self.user_id,
            token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country=country,
            device_id=user_device,
            user_agent_family=user_agent,
            endpoint="/api/v1/profile",
            result="accepted",
        ))

        # 3. Legitimate user accesses dashboard
        events.append(self.build_event(
            event_id="evt-normal-003",
            event_type="token_used",
            time_offset_seconds=300,
            user_id=self.user_id,
            token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country=country,
            device_id=user_device,
            user_agent_family=user_agent,
            endpoint="/api/v1/dashboard",
            result="accepted",
        ))

        # 4. Normal token refresh / rotation: Token A -> Token B
        events.append(self.build_event(
            event_id="evt-normal-004",
            event_type="token_refreshed",
            time_offset_seconds=1800,
            user_id=self.user_id,
            token_hash=token_hash_b,
            parent_token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country=country,
            device_id=user_device,
            user_agent_family=user_agent,
            endpoint="/api/auth/refresh",
            result="accepted",
        ))

        # 5. User accesses feed using rotated Token B
        events.append(self.build_event(
            event_id="evt-normal-005",
            event_type="token_used",
            time_offset_seconds=2000,
            user_id=self.user_id,
            token_hash=token_hash_b,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country=country,
            device_id=user_device,
            user_agent_family=user_agent,
            endpoint="/api/v1/feed",
            result="accepted",
        ))

        # 6. User gracefully logs out terminating the session
        events.append(self.build_event(
            event_id="evt-normal-006",
            event_type="logout",
            time_offset_seconds=3600,
            user_id=self.user_id,
            token_hash=token_hash_b,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country=country,
            device_id=user_device,
            user_agent_family=user_agent,
            endpoint="/api/auth/logout",
            result="accepted",
        ))

        return events
