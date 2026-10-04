# Token-Family Correlator Engine

The Token-Family Correlator (`backend.correlator`) reconstructs refresh-token parent/child chains ("token families") and manages token lifecycle state from normalized events ingested by the Event Collector.

## Architecture

The unified correlation engine (`TokenFamilyCorrelator` in `backend/correlator/engine.py`) serves as the single source of truth for both in-memory state correlation and database persistence:

1. **State-Machine Model**:
   - Manages token statuses: `ACTIVE`, `ROTATED`, `REUSED`, `REVOKED`, `EXPIRED`.
   - Reconstructs lineage chains (`reconstruct_chain`) from root ancestor to leaves.
   - Provides ancestor and descendant lookups (`get_ancestors`, `get_descendants`).
   - Flags refresh-token reuse without false alerting.

2. **Database Synchronization**:
   - Synchronizes token family memberships to the `token_family_members` table.
   - Records detected reuse attempts into the `token_reuse_records` table.
   - Supports both standalone in-memory execution (for simulator/testing) and database-backed execution (for production collector).

## Data Model

The correlator works with the following domain and database models:

### In-Memory State Models (`backend.correlator.models`)
- `TokenRecord`: In-memory tracking of individual token metadata, rotation state, timestamps, and status.
- `TokenReuseRecord`: Record of detected replay or reuse attempts with full chain context.
- `TokenStatus`: Enum representing lifecycle states (`active`, `rotated`, `reused`, `revoked`, `expired`).

### Database Persistence (`backend.collector.db`)
- `token_family_members`: SQL table tracking persistent token family links and rotation timestamps.
- `token_reuse_records`: SQL table storing reuse events flagged during real-time event ingestion.

## Usage

### In-Memory State Machine
```python
from backend.correlator import TokenFamilyCorrelator

correlator = TokenFamilyCorrelator()
correlator.process_event(event_data)
chain = correlator.reconstruct_chain("token_hash_value")
reuse_records = correlator.get_reuse_records()
```

### Database-Backed Processing
```python
from backend.correlator import process_event, reconstruct_chain
from backend.collector.db import get_session

db_session = get_session()
try:
    process_event(event_data, db_session=db_session)
    chain = reconstruct_chain("token_hash_value", db_session=db_session)
finally:
    db_session.close()
```
