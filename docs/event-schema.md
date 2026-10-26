# TokenLine Canonical Event Schema & Cross-Component Integration

## 1. Overview

TokenLine standardizes security telemetry and audit event generation, delivery, and correlation across four core components:
1. **Demo Authentication App** (`demo-app/`): Web application emitting real-time authentication events during user login, token refresh, and logout.
2. **Event Collector** (`backend/collector/`): Hardened ingestion service validating JSON schema, verifying API credentials, guarding against raw credential leakage, and persisting audit records.
3. **Safe Token Attack Simulator** (`simulator/`): Deterministic synthetic attack generator executing realistic threat scenarios (replay, refresh reuse, concurrent use, impossible travel, token revocation/expiration).
4. **Token-Family Correlator** (`backend/correlator/`): State-machine engine that reconstructs refresh-token lineage chains, tracks rotation status, and flags confirmed token reuse.

---

## 2. Canonical Event Types

TokenLine defines 12 canonical event types:

| Event Type | Producer | Semantics & Outcome |
| :--- | :--- | :--- |
| `token_issued` | Demo App, Simulator | Initial issuance of a refresh/access token pair following valid user authentication (`result: accepted`). |
| `token_used` | Demo App, Simulator | Access token presented to authorize access to protected resources (`result: accepted`). |
| `token_refreshed` | Demo App, Simulator | Successful single-use refresh token rotation, yielding a successor token (`result: accepted`). |
| `token_revoked` | Demo App, Simulator | Administrative or voluntary token invalidation (`result: accepted`). |
| `token_expired` | Demo App, Simulator | Use attempt using an expired token (`result: rejected`). |
| `logout` | Demo App, Simulator | Explicit user logout revoking active session and token family (`result: accepted`). |
| `refresh_reuse_detected` | Demo App, Simulator | Attempted presentation of an already-rotated refresh token, indicating token theft or family compromise (`result: rejected`). |
| `suspicious_location` | Anomaly Detector, Simulator | Authentication attempt from an anomalous geographic origin (`result: rejected` or `accepted`). |
| `suspicious_device` | Anomaly Detector, Simulator | Authentication attempt from an unknown or mismatched device fingerprint (`result: rejected` or `accepted`). |
| `replay_detected` | Correlator, Simulator | Confirmed duplicate or captured token replay attempt (`result: rejected`). |
| `login_failed` | Demo App, Simulator | Failed primary authentication (e.g. incorrect password or unknown username) prior to token issuance (`result: rejected`). |
| `token_rejected` | Demo App, Simulator | Presentation of a malformed, revoked, or non-existent token (`result: rejected`). |

---

## 3. Schema Specification (`schema/event.schema.json`)

All events conform to the JSON Schema Draft-07 specification.

### 3.1 Field Definitions

| Field Name | Type | Presence | Validation Rules / Format | Description |
| :--- | :--- | :--- | :--- | :--- |
| `event_id` | `string` | **Required** | Max length: 128 | Unique event identifier (e.g., `evt-a1b2c3d4`). |
| `event_type` | `string` | **Required** | Enum of 12 canonical types | The canonical event category. |
| `time` | `string` | **Required** | ISO 8601 date-time UTC (`YYYY-MM-DDTHH:MM:SSZ`) | Timestamp when the event occurred. |
| `user_id` | `string` | **Required** | Max length: 128 | Unique user identifier (e.g., `user-1234`). |
| `token_hash` | `string` / `null` | Optional | Pattern: `^(hash_)?[0-9a-fA-F]{12,64}$` | HMAC-SHA256 digest of the token identifier. Omitted or null for `login_failed`. |
| `token_family` | `string` / `null` | Optional | Max length: 128 | Identifier grouping all rotated tokens originating from a single login session. |
| `parent_token_hash`| `string` / `null` | Optional | Pattern: `^(hash_)?[0-9a-fA-F]{12,64}$` | HMAC digest of the predecessor token that was rotated into `token_hash`. |
| `ip_hash` | `string` | **Required** | Pattern: `^(hash_)?[0-9a-fA-F]{12,64}$` | Privacy-preserving truncated SHA-256 digest of the client IP address. |
| `country` | `string` / `null` | Optional | Pattern: `^[A-Z]{2}$` | Two-letter ISO-3166-1 alpha-2 country code. |
| `device_id` | `string` | **Required** | Max length: 128 | Session identifier or client device fingerprint. |
| `user_agent_family`| `string` / `null` | Optional | Max length: 128 | Extracted browser family (e.g., `Chrome`, `Firefox`, `Safari`). |
| `endpoint` | `string` / `null` | Optional | Max length: 512 | Target HTTP path (e.g., `/auth/login`, `/auth/refresh`). |
| `result` | `string` | **Required** | Enum: `["accepted", "rejected"]` | Outcome of the authentication or access attempt. |
| `schema_version` | `string` | Optional | Max length: 16 | Event schema version (e.g. `1.0.0`). |
| `source` | `string` | Optional | Max length: 64 | Originating producer component (`demo_app`, `simulator`). |
| `is_simulation` | `boolean` | Optional | Boolean (`true` or `false`) | Explicit marker distinguishing synthetic simulator data from live observations. |

### 3.2 Rules for Unavailable Context (No Fabrication)

To preserve telemetry integrity and avoid false alerts:
- **No Synthetic IP / User-Agent Defaults:** When client headers are missing, omit `user_agent_family` rather than fabricating `'Mozilla/5.0'`. If client IP cannot be legitimately determined, defer or reject event creation rather than defaulting to `'127.0.0.1'`.
- **No Fabricated Token Hashes:** For primary authentication failures (`login_failed`), no token was ever issued. Omit `token_hash` entirely rather than inventing `'root-token'`.
- **No Fabricated Token Families:** If a token does not belong to a known family or is unauthenticated, omit `token_family` rather than inventing `'family-unknown'`.
- **No Fabricated Geographic Context:** Omit `country` unless legitimately resolved from geo-IP headers (never default to `'IN'`).
- **No Hardcoded Endpoints:** Capture `req.originalUrl` or omit `endpoint` (never default to `'/auth/login'`).

---

## 4. Distinction: Authentication Failure vs. Confirmed Replay

A fundamental architectural principle of TokenLine is the strict separation between standard authentication failures and confirmed token replay attacks:

1. **Authentication Failure (`login_failed`):**
   - Occurs when a user provides an incorrect password or non-existent username at `/auth/login`.
   - **Outcome:** `result: rejected`.
   - **Correlator Impact:** No token hash exists. Correlator safely ignores the event without altering token family states or generating false security incidents.
   - **Misclassification Bug Fixed:** Previously, the demo app mapped `login_failed` to `replay_detected`. This has been eliminated.

2. **Refresh Failure (`token_rejected`):**
   - Occurs when a client submits a non-existent, expired, or syntactically invalid token to `/auth/refresh`.
   - **Outcome:** `result: rejected`.
   - **Correlator Impact:** The token was not previously registered as rotated. Correlator does not flag family compromise.
   - **Misclassification Bug Fixed:** Previously, the demo app mapped failed refresh attempts to `replay_detected`. Now mapped to `token_rejected`.

3. **Confirmed Refresh Token Reuse (`refresh_reuse_detected`):**
   - Occurs when a client presents a valid refresh token that **has already been rotated** and superseded by a child token.
   - **Outcome:** `result: rejected`.
   - **Security Action:** Invalidate the entire token family and revoke the associated user session.
   - **Correlator Impact:** The correlator matches `token_hash` against rotated family members, records a `TokenReuseRecord`, and flags confirmed theft.

4. **Confirmed Token Replay (`replay_detected`):**
   - Emitted exclusively when the application or correlator identifies verified replay of an already consumed one-time token or signature.

---

## 5. Representative Canonical Payloads

### 5.1 Successful Login (`token_issued`)
```json
{
  "event_id": "evt-7a8b9c0d",
  "event_type": "token_issued",
  "time": "2026-10-26T14:30:00Z",
  "user_id": "usr-8821",
  "token_hash": "a4d3b8f1c29e4b7a11d2e3f4",
  "token_family": "fam-4921a8f0",
  "ip_hash": "e3b0c44298fc1c14",
  "device_id": "sess-99b1c2d3",
  "user_agent_family": "Mozilla",
  "endpoint": "/auth/login",
  "result": "accepted",
  "schema_version": "1.0.0",
  "source": "demo_app",
  "is_simulation": false
}
```

### 5.2 Failed Login (`login_failed`) — No Token Hash Fabricated
```json
{
  "event_id": "evt-11223344",
  "event_type": "login_failed",
  "time": "2026-10-26T14:31:15Z",
  "user_id": "demo-user",
  "ip_hash": "e3b0c44298fc1c14",
  "device_id": "dev-unauthenticated",
  "user_agent_family": "Chrome",
  "endpoint": "/auth/login",
  "result": "rejected",
  "schema_version": "1.0.0",
  "source": "demo_app",
  "is_simulation": false
}
```

### 5.3 Refresh Token Failure (`token_rejected`)
```json
{
  "event_id": "evt-55667788",
  "event_type": "token_rejected",
  "time": "2026-10-26T14:32:00Z",
  "user_id": "usr-8821",
  "token_hash": "f1e2d3c4b5a6978811223344",
  "token_family": "fam-4921a8f0",
  "ip_hash": "e3b0c44298fc1c14",
  "device_id": "sess-99b1c2d3",
  "user_agent_family": "Chrome",
  "endpoint": "/auth/refresh",
  "result": "rejected",
  "schema_version": "1.0.0",
  "source": "demo_app",
  "is_simulation": false
}
```

### 5.4 Confirmed Token Reuse (`refresh_reuse_detected`)
```json
{
  "event_id": "evt-9900aabb",
  "event_type": "refresh_reuse_detected",
  "time": "2026-10-26T14:33:45Z",
  "user_id": "usr-8821",
  "token_hash": "a4d3b8f1c29e4b7a11d2e3f4",
  "token_family": "fam-4921a8f0",
  "ip_hash": "d41d8cd98f00b204",
  "device_id": "sess-attacker-01",
  "user_agent_family": "curl",
  "endpoint": "/auth/refresh",
  "result": "rejected",
  "schema_version": "1.0.0",
  "source": "demo_app",
  "is_simulation": false
}
```

### 5.5 Synthetic Scenario Data (`simulator`)
```json
{
  "event_id": "sim-evt-replay-001",
  "event_type": "replay_detected",
  "time": "2026-08-16T10:05:00Z",
  "user_id": "sim-user-1",
  "token_hash": "hash_a1b2c3d4e5f6",
  "token_family": "fam-sim-100",
  "ip_hash": "hash_f1e2d3c4b5a6",
  "device_id": "sim-device-replay",
  "endpoint": "/api/v1/resource",
  "result": "rejected",
  "schema_version": "1.0.0",
  "source": "simulator",
  "is_simulation": true
}
```

---

## 6. Collector Ingestion API & Delivery Architecture

### 6.1 Endpoint & Authentication
- **URL:** `POST /events` (or `POST /api/events`)
- **Headers:**
  - `Content-Type: application/json`
  - `X-API-Key: <COLLECTOR_INGEST_API_KEY>` or `Authorization: Bearer <COLLECTOR_INGEST_API_KEY>`
- **Authorization Requirement:** Caller must possess `ingest` or `admin` role. In production mode, published default keys are rejected on startup.

### 6.2 Response Formats

- **Success (HTTP 201 Created):**
  ```json
  { "status": "event persisted" }
  ```
- **Existing Event / Idempotent Duplicate (HTTP 200 OK):**
  ```json
  { "status": "event already exists" }
  ```
- **Schema Validation Rejection (HTTP 400 Bad Request):**
  ```json
  {
    "error": "Schema validation failed",
    "message": "'result' is a required property",
    "path": []
  }
  ```
- **Raw Credential Protection Rejection (HTTP 400 Bad Request):**
  ```json
  {
    "error": "Security validation failed",
    "message": "Raw credentials (such as JWTs or authorization headers) are not allowed in event payloads: Raw JWT credential detected."
  }
  ```
- **Authentication Failure (HTTP 401 Unauthorized):**
  ```json
  {
    "error": "Unauthorized",
    "message": "Invalid authentication credentials"
  }
  ```

### 6.3 Demo App Delivery & Retry Strategy

The demo application delivers events asynchronously with strict error classification:
1. **HTTP 200/201 (Success):** Log confirmation and return success.
2. **HTTP 400 (Client/Schema Rejection):** Log rejection error. Do NOT retry (payload will not become valid on retry).
3. **HTTP 401/403 (Auth Rejection):** Log authentication error. Do NOT retry. Never expose API keys in error logs.
4. **HTTP 5xx (Server Error):** Execute bounded retry (up to 2 retries) with backoff.
5. **Network Connection Error / Timeout:** Execute bounded retry (up to 2 retries). If collector is offline, fail gracefully without crashing user authentication flows.

---

## 7. Schema Versioning & Backward Compatibility

- **Version Header:** Canonical events specify `schema_version` (default: `"1.0.0"`).
- **Additive Compatibility:** Additional non-sensitive fields may be added as optional properties.
- **Strict Mode:** `additionalProperties: false` ensures unauthorized or raw credentials cannot be slipped in under arbitrary property names.
- **Database Migrations:** Forward migrations (`001` through `004`) ensure database tables adapt seamlessly to optional and new canonical fields.
