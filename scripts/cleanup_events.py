"""Delete event data older than EVENT_RETENTION_DAYS from the configured database."""
import json
import os
import sys

REPOSITORY_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPOSITORY_ROOT not in sys.path:
    sys.path.insert(0, REPOSITORY_ROOT)

from dotenv import load_dotenv

load_dotenv()

from backend.collector.db import delete_expired_events


def main():
    raw_days = os.environ.get("EVENT_RETENTION_DAYS", "365")
    try:
        days = int(raw_days)
    except ValueError as exc:
        raise SystemExit("EVENT_RETENTION_DAYS must be a positive integer") from exc
    if days < 1:
        raise SystemExit("EVENT_RETENTION_DAYS must be a positive integer")

    result = delete_expired_events(days)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
