# TokenLine Architecture

TokenLine reconstructs authentication token and session lifecycles from security events into visual, explainable timelines.

## Core Components

### 1. Ingestion & Event Collector (`backend.collector`)
- Flask-based REST service receiving authentication events at `/events`.
- Validates all incoming payloads against `schema/event.schema.json`.
- Enforces strict credential safety by stripping/rejecting raw credentials (JWTs, Bearer headers).
- Persists events to SQLite/PostgreSQL storage.

### 2. Unified Correlation Engine (`backend.correlator`)
- **Single Production Correlator**: `TokenFamilyCorrelator` (`backend.correlator.engine`).
- Reconstructs parent-child token lineage chains across rotation generations.
- Tracks token state machine: `ACTIVE`, `ROTATED`, `REUSED`, `REVOKED`, `EXPIRED`.
- Detects refresh token reuse attacks in real-time.
- Supports both high-speed in-memory state tracking and transactional database synchronization.

### 3. Attack Scenario Simulator (`simulator`)
- Deterministic synthetic generator for realistic attack flows:
  - Token Replay
  - Refresh-Token Reuse
  - Revoked-Token Use (Use After Logout)
  - Concurrent Use
  - Impossible Travel

### 4. Interactive Dashboard (`frontend`)
- Dark-mode developer and security analyst interface.
- Renders chronological session timelines, token family trees, geographic travel maps, and explainable security alerts.
