from typing import List, Dict, Any, Optional
from datetime import datetime
from simulator.base import BaseScenarioGenerator


class ConcurrentUseScenarioGenerator(BaseScenarioGenerator):
    """
    Scenario 4: Concurrent Use
    Simulates the same token being used concurrently from two distinct
    devices/IPs within an impossibly tight or overlapping time window.
    """

    def __init__(
        self,
        seed: Optional[int] = 42,
        base_time: Optional[datetime] = None,
        user_id: str = "user-synthetic-04",
    ):
        super().__init__(seed=seed, base_time=base_time)
        self.user_id = user_id

    def generate(self) -> List[Dict[str, Any]]:
        token_hash = self._hash(f"{self.user_id}-shared-token-{self.seed}")
        token_family = f"family-concurrent-{self.seed}"

        device_1 = "device-workstation-office"
        ip_hash_1 = self._hash(f"ip-office-lan-{self.seed}")

        device_2 = "device-rogue-clone"
        ip_hash_2 = self._hash(f"ip-remote-tunnel-{self.seed}")

        events = []

        # 1. Token issued
        events.append(self.build_event(
            event_id="evt-concurrent-001",
            event_type="token_issued",
            time_offset_seconds=0,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=ip_hash_1,
            country="US",
            device_id=device_1,
            user_agent_family="Edge",
            endpoint="/api/auth/login",
            result="accepted"
        ))

        # 2. Token used legitimately from Device 1
        events.append(self.build_event(
            event_id="evt-concurrent-002",
            event_type="token_used",
            time_offset_seconds=60,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=ip_hash_1,
            country="US",
            device_id=device_1,
            user_agent_family="Edge",
            endpoint="/api/v1/documents",
            result="accepted"
        ))

        # 3. Concurrent use of the same token from Device 2 (5 seconds later)
        events.append(self.build_event(
            event_id="evt-concurrent-003",
            event_type="token_used",
            time_offset_seconds=65,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=ip_hash_2,
            country="DE",
            device_id=device_2,
            user_agent_family="Go-http-client",
            endpoint="/api/v1/documents/export",
            result="accepted"
        ))

        # 4. Follow-up flag/event indicating suspicious device concurrence
        events.append(self.build_event(
            event_id="evt-concurrent-004",
            event_type="suspicious_device",
            time_offset_seconds=70,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=ip_hash_2,
            country="DE",
            device_id=device_2,
            user_agent_family="Go-http-client",
            endpoint="/api/v1/documents/export",
            result="rejected"
        ))

        return events
