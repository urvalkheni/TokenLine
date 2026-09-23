from typing import List, Dict, Any, Optional
from datetime import datetime
from simulator.base import BaseScenarioGenerator


class ImpossibleTravelScenarioGenerator(BaseScenarioGenerator):
    """
    Scenario 5: Impossible Travel
    Simulates a token being presented from two distant geographical locations
    (e.g., India to US) within a time window (e.g., 5 minutes) physically
    impossible for standard human transit.
    """

    def __init__(
        self,
        seed: Optional[int] = 42,
        base_time: Optional[datetime] = None,
        user_id: str = "user-synthetic-05",
    ):
        super().__init__(seed=seed, base_time=base_time)
        self.user_id = user_id

    def generate(self) -> List[Dict[str, Any]]:
        token_hash = self._hash(f"{self.user_id}-travel-token-{self.seed}")
        token_family = f"family-travel-{self.seed}"

        # Location 1: Mumbai, India (IN)
        ip_hash_loc1 = self._hash(f"ip-mumbai-isp-{self.seed}")
        device_loc1 = "device-traveler-laptop"

        # Location 2: New York, USA (US)
        ip_hash_loc2 = self._hash(f"ip-ny-datacenter-{self.seed}")
        device_loc2 = "device-traveler-laptop"

        events = []

        # 1. User logs in from India (IN)
        events.append(self.build_event(
            event_id="evt-travel-001",
            event_type="token_issued",
            time_offset_seconds=0,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=ip_hash_loc1,
            country="IN",
            device_id=device_loc1,
            user_agent_family="Chrome",
            endpoint="/api/auth/login",
            result="accepted"
        ))

        # 2. User accesses resources from India at T + 1 min
        events.append(self.build_event(
            event_id="evt-travel-002",
            event_type="token_used",
            time_offset_seconds=60,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=ip_hash_loc1,
            country="IN",
            device_id=device_loc1,
            user_agent_family="Chrome",
            endpoint="/api/v1/profile",
            result="accepted"
        ))

        # 3. Same token presented 4 minutes later (T + 5 min) from the United States (US)
        events.append(self.build_event(
            event_id="evt-travel-003",
            event_type="suspicious_location",
            time_offset_seconds=300,
            user_id=self.user_id,
            token_hash=token_hash,
            token_family=token_family,
            ip_hash=ip_hash_loc2,
            country="US",
            device_id=device_loc2,
            user_agent_family="Chrome",
            endpoint="/api/v1/profile",
            result="rejected"
        ))

        return events
