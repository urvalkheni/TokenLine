import json
import requests
import os
import sys

URL = "http://127.0.0.1:5000/events"
DEFAULT_DATASET = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "synthetic", "normal.json")


def main():
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DATASET

    if not os.path.exists(dataset_path):
        print(f"Dataset file not found at {dataset_path}")
        sys.exit(1)

    with open(dataset_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    print(f"Found {len(events)} events in dataset ({os.path.basename(dataset_path)}). Starting submission to {URL}...")
    
    success_count = 0
    for event in events:
        try:
            res = requests.post(URL, json=event)
            if res.status_code in [200, 201]:
                print(f"Event {event['event_id']} ({event['event_type']}): Success ({res.status_code})")
                success_count += 1
            else:
                print(f"Event {event['event_id']} ({event['event_type']}): Failed with status {res.status_code} - {res.text}")
        except Exception as e:
            print(f"Failed to submit event {event['event_id']}: {e}")

    print(f"\nSubmission complete: {success_count}/{len(events)} events accepted.")


if __name__ == "__main__":
    main()
