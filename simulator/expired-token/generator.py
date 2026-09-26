from typing import List, Dict, Any, Optional
from datetime import datetime
from simulator.base import BaseScenarioGenerator


class ExpiredTokenScenarioGenerator(BaseScenarioGenerator):
    """
    Scenario: Expired Token Lifecycle
    Simulates a token lifecycle where a token is issued, used legitimately, reaches
    its expiration threshold, and is subsequently presented in an invalid usage attempt:
    1. User authenticates and receives an active token.
    2. Legitimate token usage within its valid lifetime.
    3. Token expiration event recorded after lifespan expires.
    4. Subsequent invalid use attempt with the expired token is rejected.
    """

    def __init__(
        self,
        seed: Optional[int] = 42,
        base_time: Optional[datetime] = None,
        user_id: str = "user-synthetic-expired",
    ):
        super().__init__(seed=seed, base_time=base_time)
        self.user_id = user_id

    def generate(self) -> List[Dict[str, Any]]:
        token_hash = self._hash(f"{self.user_id}-session-token-{self.seed}")
        token_family = f"family-expired-{self.seed}"

        user_ip_hash = self._hash(f"legit-ip-mobile-{self.seed}")
        user_device = "device-mobile-client"
        user_agent = "MobileSafari"
        country = "US"

        events = []

        # 1. User logs in -> Token Issued
        events.append(self.build_event(
            event_id="evt-expired-001",
            event_type="token_issued",
            time_offset_seconds=0,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country=country,
            device_id=user_device,
            user_agent_family=user_agent,
            endpoint="/api/auth/login",
            result="accepted",
        ))

        # 2. Legitimate user uses the token within active lifespan
        events.append(self.build_event(
            event_id="evt-expired-002",
            event_type="token_used",
            time_offset_seconds=300,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country=country,
            device_id=user_device,
            user_agent_family=user_agent,
            endpoint="/api/v1/profile",
            result="accepted",
        ))

        # 3. Token expiration reaches TTL / expiration threshold (1 hour later)
        events.append(self.build_event(
            event_id="evt-expired-003",
            event_type="token_expired",
            time_offset_seconds=3600,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country=country,
            device_id=user_device,
            user_agent_family=user_agent,
            endpoint="/api/v1/profile",
            result="accepted",
        ))

        # 4. Subsequent invalid use attempt with the expired token (rejected)
        events.append(self.build_event(
            event_id="evt-expired-004",
            event_type="token_used",
            time_offset_seconds=3700,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country=country,
            device_id=user_device,
            user_agent_family=user_agent,
            endpoint="/api/v1/profile",
            result="rejected",
        ))

        return events
