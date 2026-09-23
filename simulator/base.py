import os
import json
import random
import hashlib
import jsonschema
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional


SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "schema",
    "event.schema.json"
)

try:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        EVENT_SCHEMA = json.load(f)
except Exception:
    EVENT_SCHEMA = None


class BaseScenarioGenerator:
    """
    Base class for synthetic authentication attack scenario generation.
    Enforces deterministic seeding, privacy-preserving hashing, and JSON Schema validation.
    """

    def __init__(self, seed: Optional[int] = 42, base_time: Optional[datetime] = None):
        self.seed = seed
        self.rng = random.Random(seed)
        self.base_time = base_time or datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
        self.events: List[Dict[str, Any]] = []

    def _hash(self, val: str) -> str:
        """Returns a 16-character hex hash of a synthetic input string."""
        h = hashlib.sha256(val.encode("utf-8")).hexdigest()
        return f"hash_{h[:12]}"

    def build_event(
        self,
        event_id: str,
        event_type: str,
        time_offset_seconds: int,
        user_id: str,
        token_hash: str,
        ip_hash: str,
        device_id: str,
        result: str,
        token_family: Optional[str] = None,
        parent_token_hash: Optional[str] = None,
        country: Optional[str] = None,
        user_agent_family: Optional[str] = None,
        endpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Constructs and validates a single schema-compliant event dictionary."""
        event_time = (self.base_time + timedelta(seconds=time_offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        event: Dict[str, Any] = {
            "event_id": event_id,
            "event_type": event_type,
            "time": event_time,
            "user_id": user_id,
            "token_hash": token_hash,
            "ip_hash": ip_hash,
            "device_id": device_id,
            "result": result,
        }

        if token_family:
            event["token_family"] = token_family
        if parent_token_hash:
            event["parent_token_hash"] = parent_token_hash
        if country:
            event["country"] = country
        if user_agent_family:
            event["user_agent_family"] = user_agent_family
        if endpoint:
            event["endpoint"] = endpoint

        # Validate against schema
        self.validate_event(event)
        return event

    def validate_event(self, event: Dict[str, Any]) -> bool:
        """Validates an event against the TokenLine JSON Schema."""
        if EVENT_SCHEMA:
            jsonschema.validate(instance=event, schema=EVENT_SCHEMA)
        return True

    def generate(self) -> List[Dict[str, Any]]:
        """Abstract method to be implemented by scenario generators."""
        raise NotImplementedError("Subclasses must implement generate()")
