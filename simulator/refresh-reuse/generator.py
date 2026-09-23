from typing import List, Dict, Any, Optional
from datetime import datetime
from simulator.base import BaseScenarioGenerator


class RefreshReuseScenarioGenerator(BaseScenarioGenerator):
    """
    Scenario 2: Refresh-Token Reuse
    Simulates token rotation (Token A -> Token B) followed by an attacker
    attempting to present the already-rotated Token A to obtain a new token.
    This scenario is designed to trigger the Token-Family Correlator's reuse detection.
    """

    def __init__(
        self,
        seed: Optional[int] = 42,
        base_time: Optional[datetime] = None,
        user_id: str = "user-synthetic-02",
    ):
        super().__init__(seed=seed, base_time=base_time)
        self.user_id = user_id

    def generate(self) -> List[Dict[str, Any]]:
        token_hash_a = self._hash(f"{self.user_id}-token-root-A-{self.seed}")
        token_hash_b = self._hash(f"{self.user_id}-token-child-B-{self.seed}")
        token_hash_c_attacker = self._hash(f"{self.user_id}-token-attacker-C-{self.seed}")
        token_family = f"family-refresh-{self.seed}"

        legit_ip_hash = self._hash(f"legit-ip-{self.seed}")
        legit_device = "device-user-phone"

        attacker_ip_hash = self._hash(f"attacker-ip-{self.seed}")
        attacker_device = "device-adversary-bot"

        events = []

        # 1. Root token issued to user
        events.append(self.build_event(
            event_id="evt-reuse-001",
            event_type="token_issued",
            time_offset_seconds=0,
            user_id=self.user_id,
            token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=legit_ip_hash,
            country="US",
            device_id=legit_device,
            user_agent_family="MobileSafari",
            endpoint="/api/auth/login",
            result="accepted"
        ))

        # 2. Legitimate user uses token A
        events.append(self.build_event(
            event_id="evt-reuse-002",
            event_type="token_used",
            time_offset_seconds=300,
            user_id=self.user_id,
            token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=legit_ip_hash,
            country="US",
            device_id=legit_device,
            user_agent_family="MobileSafari",
            endpoint="/api/v1/feed",
            result="accepted"
        ))

        # 3. Legitimate user rotates token: Refresh Token A -> Token B
        events.append(self.build_event(
            event_id="evt-reuse-003",
            event_type="token_refreshed",
            time_offset_seconds=1800,
            user_id=self.user_id,
            token_hash=token_hash_b,
            parent_token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=legit_ip_hash,
            country="US",
            device_id=legit_device,
            user_agent_family="MobileSafari",
            endpoint="/api/auth/refresh",
            result="accepted"
        ))

        # 4. User uses the newly rotated Token B
        events.append(self.build_event(
            event_id="evt-reuse-004",
            event_type="token_used",
            time_offset_seconds=2000,
            user_id=self.user_id,
            token_hash=token_hash_b,
            token_family=token_family,
            ip_hash=legit_ip_hash,
            country="US",
            device_id=legit_device,
            user_agent_family="MobileSafari",
            endpoint="/api/v1/feed",
            result="accepted"
        ))

        # 5. Attacker presents old/rotated Token A in a refresh attempt
        events.append(self.build_event(
            event_id="evt-reuse-005",
            event_type="token_refreshed",
            time_offset_seconds=2100,
            user_id=self.user_id,
            token_hash=token_hash_c_attacker,
            parent_token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=attacker_ip_hash,
            country="RU",
            device_id=attacker_device,
            user_agent_family="Curl",
            endpoint="/api/auth/refresh",
            result="rejected"
        ))

        return events
