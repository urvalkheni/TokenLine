from typing import List, Dict, Any, Optional
from datetime import datetime
from simulator.base import BaseScenarioGenerator


class ReplayScenarioGenerator(BaseScenarioGenerator):
    """
    Scenario 1: Token Replay
    Simulates a workflow where a valid token is issued, used legitimately,
    and then replayed by an adversary from an unauthorized client/device.
    """

    def __init__(
        self,
        seed: Optional[int] = 42,
        base_time: Optional[datetime] = None,
        user_id: str = "user-synthetic-01",
    ):
        super().__init__(seed=seed, base_time=base_time)
        self.user_id = user_id

    def generate(self) -> List[Dict[str, Any]]:
        token_hash_a = self._hash(f"{self.user_id}-token-alpha-{self.seed}")
        token_family = f"family-replay-{self.seed}"
        
        user_ip_hash = self._hash(f"legit-ip-home-{self.seed}")
        user_device = "device-legit-laptop"

        attacker_ip_hash = self._hash(f"adversary-ip-{self.seed}")
        attacker_device = "device-unknown-adversary"

        events = []

        # 1. User logs in -> Token Issued
        events.append(self.build_event(
            event_id="evt-replay-001",
            event_type="token_issued",
            time_offset_seconds=0,
            user_id=self.user_id,
            token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country="US",
            device_id=user_device,
            user_agent_family="Chrome",
            endpoint="/api/auth/login",
            result="accepted"
        ))

        # 2. Legitimate user uses the token
        events.append(self.build_event(
            event_id="evt-replay-002",
            event_type="token_used",
            time_offset_seconds=120,
            user_id=self.user_id,
            token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country="US",
            device_id=user_device,
            user_agent_family="Chrome",
            endpoint="/api/v1/profile",
            result="accepted"
        ))

        # 3. Legitimate user makes another normal API call
        events.append(self.build_event(
            event_id="evt-replay-003",
            event_type="token_used",
            time_offset_seconds=240,
            user_id=self.user_id,
            token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=user_ip_hash,
            country="US",
            device_id=user_device,
            user_agent_family="Chrome",
            endpoint="/api/v1/dashboard",
            result="accepted"
        ))

        # 4. Adversary intercepts and replays token A from an untrusted origin
        events.append(self.build_event(
            event_id="evt-replay-004",
            event_type="replay_detected",
            time_offset_seconds=300,
            user_id=self.user_id,
            token_hash=token_hash_a,
            token_family=token_family,
            ip_hash=attacker_ip_hash,
            country="RO",
            device_id=attacker_device,
            user_agent_family="Python-requests",
            endpoint="/api/v1/wallet",
            result="rejected"
        ))

        return events
