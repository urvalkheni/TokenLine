# TokenLine Demo Authentication Application

## 1. Purpose
This is a minimal, self-contained demonstration authentication application for TokenLine. It generates realistic authentication-token lifecycle events without storing raw sensitive tokens or relying on external identity providers.

## 2. Architecture
The application is built using Node.js, Express, and JSON Web Tokens (JWT). It features:
- In-memory session tracking.
- In-memory refresh token family state, keeping track of parent-successor token rotation.
- An abstracted event interface that mimics emissions to TokenLine.
- Cryptographically secure opaque refresh tokens stored only as HMAC/SHA-256 hashes.

## 3. Requirements
- Node.js
- npm

## 4. Installation
```bash
npm install
```

## 5. Configuration
Copy the `.env.example` file to `.env`:
```bash
cp .env.example .env
```
Ensure `JWT_SECRET` is set to something local and random for testing. Never commit production secrets.

## 6. Synthetic Credentials
A single synthetic user is hardcoded for demonstration purposes:
- **Username**: `demo-user`
- **Password**: `DemoPassword123!`

Do not use real credentials or connect real user stores to this demo.

## 7. Starting the Server
```bash
npm start
```
The server will start on port 3000 by default.

## 8. Login API
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "demo-user", "password": "DemoPassword123!"}'
```
Returns `accessToken`, `refreshToken`, and `sessionId`.

## 9. Protected API
Requires a valid `accessToken`.
```bash
curl -X GET http://localhost:3000/api/profile \
  -H "Authorization: Bearer <your_access_token>"
```

## 10. Refresh API
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<your_refresh_token>"}'
```

## 11. Refresh-Token Rotation Behavior
When you use a valid refresh token, it is invalidated and a successor (new) refresh token is returned alongside a new access token. The tokens are tracked within a "Token Family."

## 12. Old Refresh-Token Rejection
If a previously used refresh token is submitted again, the application detects this as suspicious "refresh token reuse." It will instantly invalidate the old token, revoke the entire token family, and revoke the active session. This securely invalidates all future requests from any client in that session.

## 13. Logout
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Authorization: Bearer <your_access_token>"
```
This revokes the active session.

## 14. Session Revocation
When a session is revoked (via logout or suspicious activity like refresh-token reuse), all further attempts to use access tokens or refresh tokens bound to that session will be rejected.

## 15. Event Integration
The abstract `eventService.js` logs TokenLine lifecycle events to the console. Emitted events include `login`, `token_issued`, `token_used`, `token_refreshed`, `token_revoked`, `logout`, and `refresh_reuse_detected`. Raw sensitive tokens and passwords are fundamentally excluded from event payloads.

## 16. Security/Logging Behavior
- Raw passwords and raw refresh tokens are NEVER logged.
- Only a privacy-preserving identifier (HMAC/SHA-256) of the refresh token is tracked internally and emitted in events.
- Sensitive values passed in the `Authorization` header are never echoed to standard out.

## 17. Running Automated Tests
The application is fully covered by an integration test suite using Jest and Supertest.
```bash
npm test
```

## 18. Complete Example Authentication Flow

1. **Login:** Capture `accessToken` and `refreshToken` A.
2. **Access API:** GET `/api/profile` with `accessToken` -> Success.
3. **Refresh:** POST `/auth/refresh` with `refreshToken` A -> Success, returns `refreshToken` B and new `accessToken`.
4. **Try old Refresh:** POST `/auth/refresh` with `refreshToken` A -> Rejected (Reuse Detected). Session is revoked.
5. **Use new Refresh:** POST `/auth/refresh` with `refreshToken` B -> Rejected (Session Revoked).
6. **Logout:** If user logs in again, they can call `/auth/logout` to end the session immediately.
