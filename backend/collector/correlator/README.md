# Token-Family Correlator

The Token-Family Correlator reconstructs refresh-token parent/child chains ("token families") from normalized events ingested by the Event Collector.

## Data Model

The correlator extends the database configuration with two new tables managed via SQLAlchemy:

### `token_family_members`
Tracks individual tokens, their relationship to parents, and their current rotation status.
* `token_hash` (TEXT, Primary Key): Salted hash of the token credential.
* `token_family` (TEXT): Unique ID identifying the rotation family.
* `parent_token_hash` (TEXT, Nullable): Hash of the parent token that this token replaced.
* `is_rotated` (BOOLEAN): `True` if this token has already been rotated/replaced.
* `rotated_at` (TEXT, Nullable): ISO 8601 timestamp representing when the rotation occurred.
* `superseded_by` (TEXT, Nullable): Hash of the child/replacement token.
* `user_id` (TEXT): ID of the user owning the token session.

### `token_reuse_records`
Logs refresh token reuse attempts for ingestion by a future detection engine.
* `id` (INTEGER, Primary Key): Unique row identifier.
* `token_hash` (TEXT): Hash of the replayed/rotated token.
* `token_family` (TEXT): The token family associated with the reuse.
* `reused_at` (TEXT): Time of the reuse attempt.
* `attempted_event_id` (TEXT): The Event Collector ID representing the reuse event.

---

## Operations

### Processing Events
When a `token_refreshed` event is processed:
1. The correlator checks if the parent token (`parent_token_hash`) exists.
2. If the parent exists, the new token joins the parent's `token_family`. The parent token is marked as `is_rotated = True`, and its `superseded_by` field is set to the new token's hash.
3. If the parent does not exist, a root token is provisionally created, a new family ID is generated, and the child token is linked to it.
4. If a token marked as `is_rotated = True` is presented again for usage/refresh, a reuse record is inserted into `token_reuse_records`.

### Reconstructing Chains
Given any token hash, the correlator can reconstruct the full family history from root to leaf by traversing `parent_token_hash` backward to the root and following `superseded_by` forward to find all descendants.

---

## Standalone Usage

You can run the correlator standalone to process a JSON file containing a list of events:
```python
from correlator import process_event_file

# Ingest events from a JSON file and store them in the database
process_event_file("path/to/events.json")
```

## Running Unit Tests

Run the correlator test suite:
```bash
pytest tests/unit/test_correlator.py
```
