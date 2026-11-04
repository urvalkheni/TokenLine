# TokenLine Demo Authentication Application

## 1. Purpose
This is a self-contained demonstration authentication service for TokenLine. It simulates realistic authentication-token lifecycle events (login, access, rotation, reuse detection, and logout) while demonstrating privacy-preserving HMAC token identification without storing raw credentials or relying on external Identity Providers.

## 2. Architecture
The application is built using Node.js, Express, and JSON Web Tokens (JWT). It features:
- In-memory session tracking.
- In-memory refresh token family state, maintaining parent-successor rotation relationships.
- Event emission via [`src/services/eventService.js`](src/services/eventService.js) to the TokenLine Event Collector.
- Cryptographically secure opaque refresh tokens stored only as HMAC-SHA-256 hashes (`token_hash`).
- Immediate cascade family revocation upon detecting refresh-token reuse.

## 3. Requirements
- **Node.js**: `18.0.0+` (tested on Node.js 18, 20, 22, 24)
- **npm**: `9.0.0+`

## 4. Installation
```bash
npm install
```

## 5. Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### Environment Modes and Configuration Variables

| Variable | Default (Dev) | Description |
| :--- | :--- | :--- |
| `NODE_ENV` | `development` | Environment mode (`development`, `test`, `production`). In production, strict security checks run on startup. |
| `PORT` | `3000` | Port for the demo authentication HTTP server. |
| `JWT_SECRET` | *(Test fallback in dev)* | Secret key for signing demo JWT access tokens (minimum 32 characters in production). |
| `TOKEN_HMAC_SECRET` | *(Test fallback in dev)* | Secret key used to generate privacy-preserving HMAC-SHA-256 token identifiers (minimum 32 characters in production). |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000,...` | Explicit comma-separated allowlist of allowed frontend origins (no wildcards in production). |
| `COLLECTOR_URL` | `http://127.0.0.1:5000/events` | Target Event Collector ingestion endpoint. |
| `COLLECTOR_API_KEY` | *(None / Optional in dev)* | Ingestion API key for the collector (e.g. `tokenline-ingest-secret` in dev). |

## 6. Synthetic Credentials
A single synthetic user is hardcoded for demonstration purposes:
- **Username**: `demo-user`
- **Password**: `DemoPassword123!`

> [!CAUTION]
> Never use real user credentials, and do not connect production identity databases to this demonstration service.

## 7. Starting the Server
```bash
npm start
```
The server starts on `http://127.0.0.1:3000` by default.

## 8. API Endpoints

### Login
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "demo-user", "password": "DemoPassword123!"}'
```
Returns `accessToken` (JWT), `refreshToken` (opaque hex string), and `sessionId`. Emits `token_issued` to the collector.

### Access Protected Resource
```bash
curl -X GET http://localhost:3000/api/profile \
  -H "Authorization: Bearer <your_access_token>"
```
Emits `token_used` to the collector.

### Refresh Token (Rotation)
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<your_refresh_token>"}'
```
Invalidates the presented refresh token, issues a new access token and a successor refresh token, and emits `token_refreshed` with `parent_token_hash`.

### Refresh-Token Reuse Detection
If a previously rotated refresh token is presented again to `/auth/refresh`, the demo app detects reuse, revokes the entire token family, revokes the user session, and emits `refresh_reuse_detected` to the collector.

### Logout
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Authorization: Bearer <your_access_token>"
```
Revokes the session and emits `logout` to the collector.

## 9. Security & Privacy Guarantees
- Raw passwords and raw tokens are **never** logged or emitted in event payloads.
- The service hashes refresh tokens using `crypto.createHmac('sha256', TOKEN_HMAC_SECRET)` before storing them in memory or sending event telemetry.
- Event payloads contain only salted hashes (`token_hash`, `parent_token_hash`), never raw credentials.

## 10. Running Automated Tests
Run the Jest test suite:
```bash
npm test
```
All 49 unit and integration tests run against an in-memory test environment.
