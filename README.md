# TokenLine

> **Tracking the Life of a Login Session**

TokenLine is a developer-focused, educational authentication-token lifecycle correlation, anomaly detection, and visualization platform. It reconstructs the chronological history of authentication tokens and sessions from structured security events, maps rotation lineage trees, evaluates explainable detection signals, and renders that history as an interactive timeline.

---

## Project Status

**Current Status: Implemented Prototype & Educational Platform.**

The repository contains an active, working implementation across all key components:

- **Canonical Event Schema**: Strict JSON Schema specification ([`schema/event.schema.json`](schema/event.schema.json)) validating lifecycle events.
- **Event Collector API**: Python Flask REST service ([`backend/collector/`](backend/collector/)) enforcing three-layer credential sanitization, role-based API authorization, and CORS policy.
- **Persistence & Migrations Layer**: SQLAlchemy data models and schema migration manager ([`backend/database/migrations.py`](backend/database/migrations.py)) supporting SQLite (default local) and PostgreSQL (Neon).
- **Unified Correlator & Detection Engine**: State machine ([`backend/correlator/engine.py`](backend/correlator/engine.py)) tracking token states, building parent-child rotation trees, detecting anomalies, and calculating standardized evaluation metrics ([`backend/correlator/evaluator.py`](backend/correlator/evaluator.py)).
- **Attack Simulator & Dataset Generator**: Deterministic synthetic generator ([`simulator/`](simulator/)) producing reproducible lifecycle datasets ([`data/synthetic/`](data/synthetic/)) and attack scenarios.
- **Demo Authentication Application**: Self-contained Node.js/Express service ([`demo-app/`](demo-app/)) illustrating login, token rotation, family revocation, and HMAC token privacy.
- **Security Investigation Frontends**: Interactive Single-Page Application ([`frontend/index.html`](frontend/index.html)) with dynamic SVG parent-child lineage trees and a 3D Canvas coordinate globe, plus an operational dashboard shell ([`frontend/dashboard/`](frontend/dashboard/)).
- **Comprehensive Test Suites**: Pytest suite ([`tests/`](tests/)) covering unit, migration, XSS prevention, and scenario integration tests, alongside Jest integration tests in `demo-app/`.

> [!NOTE]
> **Educational & Research Scope**: TokenLine is an educational analysis and correlation layer designed for controlled environments and synthetic datasets. It is **not** an Identity Provider (IdP), OAuth server, or production SIEM. It does not replace enterprise identity security systems such as Okta, Microsoft Entra, Auth0, Keycloak, or commercial SIEMs.

---

## The Problem

Modern applications rely on authentication artifacts such as JWT access tokens, refresh tokens, session cookies, OAuth/OIDC tokens, and application sessions. An authentication server typically knows when an artifact is issued, and may log when it expires or is revoked. During security investigations, however, the critical question is:

> *What happened to this authentication token throughout its entire lifetime?*

```text
Login
  ↓
Access token issued
  ↓
Token used from Device A
  ↓
Token refreshed (rotated)
  ↓
New successor token issued
  ↓
Old (rotated) refresh token reused by attacker
  ↓
Suspicious reuse anomaly flagged
  ↓
Token family cascaded into revocation
```

Traditional logging systems and SIEMs record these steps as disconnected events across various log streams. Analysts must manually search, aggregate, and correlate timestamps, hashes, IP addresses, and device fingerprints to understand what occurred.

TokenLine reconstructs disconnected security events into a single, connected token lineage story.

---

## System Architecture

```text
┌───────────────────────────────┐        ┌───────────────────────────────┐
│     Demo Application (Node)   │        │   Attack Simulator (Python)   │
│  - JWT & HMAC token hashing   │        │  - Deterministic generators   │
│  - Rotation & local revocation│        │  - Seed-controlled datasets  │
└───────────────┬───────────────┘        └───────────────┬───────────────┘
                │                                        │
                │         POST /events (JSON)            │
                └───────────────────┬────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   TokenLine Event Collector (Flask)                    │
│                                                                        │
│  1. Rate & Payload Size Checks (10 MB cap)                             │
│  2. JSON Schema Validation (schema/event.schema.json)                  │
│  3. Three-Layer Credential Sanitization:                               │
│     - Layer 1: Structural Hash Validation (hex or hash_ prefix)        │
│     - Layer 2: Credential-Pattern Regex (JWTs, Bearer, assignments)    │
│     - Layer 3: Shannon Entropy Anomaly Detection (entropy >= 4.0)      │
│  4. Role-Based Access Control (admin, ingest, read)                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Unified Correlation Engine (backend.correlator)          │
│                                                                        │
│  - Token Family Lineage Builder (reconstruct_chain)                    │
│  - Lifecycle State Machine (ACTIVE, ROTATED, REUSED, REVOKED, EXPIRED) │
│  - Detection Rules:                                                    │
│      TL-RULE-001 (RULE-TOKEN-REUSE)                                    │
│      TL-RULE-002 (RULE-REVOKED-USE)                                    │
│      TL-RULE-003 (RULE-EXPIRED-USE)                                    │
│      TL-RULE-004 (RULE-CONCURRENT-USE)                                 │
│      TL-RULE-005 (RULE-IMPOSSIBLE-TRAVEL)                              │
│  - Explainable Alert Generator (AlertRecord & dedup fingerprints)      │
│  - Standardized Evaluation Evaluator (TP, FP, TN, FN, Precision, F1)   │
└───────────────┬────────────────────────────────────────┬───────────────┘
                ▼                                        ▼
┌───────────────────────────────┐        ┌───────────────────────────────┐
│  Persistence Layer            │        │  REST Query API & Static UI   │
│  - events                     │        │  - GET /api/events            │
│  - token_family_members       │        │  - GET /api/families          │
│  - token_reuse_records        │        │  - GET /api/alerts            │
│  - scenario_executions        │        │  - POST /api/scenarios/<id>/run│
│  - alerts                     │        │  - GET / (Interactive SPA)    │
│  (SQLite or Neon PostgreSQL)  │        │  - GET /dashboard/            │
└───────────────────────────────┘        └───────────────────────────────┘
```

---

## Supported Runtimes

| Component | Language / Runtime | Minimum Version | Tested Versions |
| :--- | :--- | :--- | :--- |
| **Backend & Simulator** | Python | `3.12+` | Python 3.12, 3.13, 3.14 |
| **Demo Application** | Node.js | `18.0.0+` | Node.js 18, 20, 22, 24 |
| **Package Managers** | `pip` & `npm` | Standard | pip 24+, npm 9+ |

---

## Local Installation & Startup Guide

Follow this guide to get all TokenLine components running from a clean checkout.

### 1. Prerequisites

Ensure you have Python 3.12+ and Node.js 18+ installed on your system:
```bash
python3 --version
node --version
npm --version
```

### 2. Backend & Event Collector Setup

1. **Create and activate a Python virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate      # Linux / macOS
   # On Windows: .venv\Scripts\activate
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure local environment**:
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
   For local development, the default `.env` settings are pre-configured to use local SQLite (`sqlite:///./tokenline.db`) and `TOKENLINE_ENV=development`.

4. **Initialize database schema & run migrations**:
   The Event Collector automatically runs pending database migrations upon startup. You can also trigger them manually from Python:
   ```bash
   python -c "from backend.database import run_migrations; run_migrations(); print('Migrations complete!')"
   ```

5. **Start the Event Collector service**:
   ```bash
   python -m backend.collector.app
   ```
   The collector starts on `http://127.0.0.1:5000` by default.

### 3. Demo Authentication Application Setup

In a new terminal window:

1. **Navigate to the demo app directory and install dependencies**:
   ```bash
   cd demo-app
   npm install
   ```

2. **Configure demo app environment**:
   ```bash
   cp .env.example .env
   ```
   For development, default development keys are provided in `.env.example`.

3. **Start the Demo Application**:
   ```bash
   npm start
   ```
   The demo app starts on `http://127.0.0.1:3000`.

### 4. Accessing the Frontends

- **Interactive Investigation Single-Page Application**: Open `http://127.0.0.1:5000` in your web browser. This interface includes the token family visualizer, SVG lineage diagram, 3D travel anomaly globe, and scenario trigger buttons.
- **Operational Dashboard Shell**: Open `http://127.0.0.1:5000/dashboard/index.html` to inspect metrics, alerts, and recent event feeds.

---

## Configuration & Environment Variables

### Backend Collector Configuration (`.env`)

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `TOKENLINE_ENV` | `production` (if unset) | Execution environment mode: `development`, `test`, or `production`. When set to `production`, strict security checks are enforced at startup. |
| `PORT` | `5000` | Port for the Flask Event Collector HTTP service. |
| `DATABASE_URL` | `sqlite:///./tokenline.db` | SQLAlchemy connection URL. Supports local SQLite or PostgreSQL (such as hosted Neon). |
| `COLLECTOR_ADMIN_API_KEY` | *(None)* | API credential granting full administrative permissions (minimum 16 characters). |
| `COLLECTOR_INGEST_API_KEY` | *(None)* | API credential granting event ingestion permissions for `POST /events`. |
| `COLLECTOR_READ_API_KEY` | *(None)* | API credential granting read-only query permissions for dashboard APIs. |
| `COLLECTOR_API_KEYS` | *(None)* | Optional JSON mapping of `{ "key": "role" }` defining multiple keys and their assigned roles. |
| `CORS_ALLOWED_ORIGINS` | *(None)* | Comma-separated list of allowed frontend origins (e.g. `http://localhost:3000,http://127.0.0.1:3000,http://127.0.0.1:5000`). Wildcards are prohibited in production. |

### Demo Application Configuration (`demo-app/.env`)

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `NODE_ENV` | `development` | Environment mode (`development`, `test`, `production`). |
| `PORT` | `3000` | Port for the Node.js Express authentication server. |
| `JWT_SECRET` | *(Test fallback in dev)* | Secret key for signing demo access tokens (minimum 32 characters in production). |
| `TOKEN_HMAC_SECRET` | *(Test fallback in dev)* | Secret key used to compute privacy-preserving HMAC-SHA-256 token identifiers (minimum 32 characters in production). |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000,...` | Trusted origins permitted to make cross-origin requests. |
| `COLLECTOR_URL` | `http://127.0.0.1:5000/events` | Ingestion endpoint where the demo app transmits privacy-safe event metadata. |
| `COLLECTOR_API_KEY` | *(None)* | Ingestion key passed in `Authorization: Bearer <key>` when emitting events. |

---

## API Authentication & Authorization

The Collector implements role-based access control (RBAC) across three distinct roles using constant-time credential comparisons (`hmac.compare_digest`):

| Role | Permitted Actions | Associated Endpoints |
| :--- | :--- | :--- |
| **`admin`** | Full access: ingest, read, update alert status, run scenarios | All endpoints (`PATCH /api/alerts/<id>`, `POST /api/scenarios/<name>/run`, etc.) |
| **`ingest`** | Ingest security events | `POST /events`, `POST /api/events` |
| **`read`** | Query event history, family trees, alerts, scenarios | `GET /api/events`, `GET /api/families`, `GET /api/alerts`, `GET /api/scenarios` |

### Supplying Credentials

Authentication tokens can be provided in either of the following HTTP request headers:
- `Authorization: Bearer <your_api_key>`
- `X-API-Key: <your_api_key>`

### Development vs Production Safety Rules

- **Development & Test Modes (`TOKENLINE_ENV=development` or `test`)**:
  If no API keys are explicitly configured in the environment, the collector falls back to safe local keys:
  - Admin: `tokenline-admin-secret`
  - Ingest: `tokenline-ingest-secret`
  - Read: `tokenline-read-secret`
- **Production Mode (`TOKENLINE_ENV=production`)**:
  - Published fallback keys and common passwords (`admin`, `password`, `123456`, etc.) are **explicitly rejected** at startup.
  - API keys must be at least 16 characters in length.
  - `CORS_ALLOWED_ORIGINS` must be explicitly defined without wildcards (`*`).
  - Misspelled environment modes fail closed and halt the application.

---

## Running Automated Tests

### Python Backend & Simulator Test Suite

To run all automated Python unit and scenario tests:
```bash
pytest
# Or with verbose output:
pytest -v
```

The Python suite contains 170+ automated tests covering:
- Ingestion schema validation and 3-layer credential sanitization ([`tests/unit/test_collector.py`](tests/unit/test_collector.py)).
- Correlator state machine transitions and family trees ([`tests/unit/test_correlator_engine.py`](tests/unit/test_correlator_engine.py)).
- Transaction safety and rollback handling ([`tests/unit/test_transaction_safety.py`](tests/unit/test_transaction_safety.py)).
- Database migrations across SQLite and PostgreSQL ([`tests/unit/test_database_migrations.py`](tests/unit/test_database_migrations.py)).
- Alert model standard, deduplication, and classification evaluation ([`tests/unit/test_alert_standard_and_evaluation.py`](tests/unit/test_alert_standard_and_evaluation.py)).
- Synthetic attack dataset generation and scenario reproducibility ([`tests/scenarios/test_synthetic_datasets.py`](tests/scenarios/test_synthetic_datasets.py)).
- Frontend API endpoints and XSS prevention ([`tests/unit/test_frontend_api.py`](tests/unit/test_frontend_api.py), [`tests/unit/test_frontend_xss.py`](tests/unit/test_frontend_xss.py)).

### Demo Application Test Suite

To run the Node.js demo app test suite:
```bash
cd demo-app
npm test
```
The Jest suite tests JWT generation, refresh token rotation, token privacy enforcement, family revocation upon reuse, and security middleware configuration.

---

## Synthetic Scenarios & Dataset Generation

TokenLine includes an attack simulator and dataset generator designed for offline testing and deterministic verification.

### Available Canonical Scenarios

| Scenario | Identifier | Target Artifact | Description |
| :--- | :--- | :--- | :--- |
| **Normal Lifecycle** | `normal` | [`data/synthetic/normal.json`](data/synthetic/normal.json) | Baseline token issuance, legitimate use, clean refresh rotation, and logout. |
| **Refresh-Token Reuse** | `refresh-reuse` | [`data/synthetic/refresh-reuse.json`](data/synthetic/refresh-reuse.json) | Token A rotates to Token B; attacker attempts to use retired Token A again. |
| **Expired Token** | `expired-token` | [`data/synthetic/expired-token.json`](data/synthetic/expired-token.json) | Token passes its TTL; subsequent presentation is rejected. |
| **Use After Logout** | `revoked-token` | [`data/synthetic/revoked-token.json`](data/synthetic/revoked-token.json) | User logs out; attacker attempts to present the revoked token. |
| **Concurrent Use** | `concurrent-use` | [`data/synthetic/concurrent-use.json`](data/synthetic/concurrent-use.json) | Same token presented within 60 seconds from distinct devices or IP addresses. |
| **Impossible Travel** | `impossible-travel` | [`data/synthetic/impossible-travel.json`](data/synthetic/impossible-travel.json) | Same token presented from distant geographical regions within 5 minutes. |
| **Token Replay** | `replay` | Synthetic Stream | Legitimate token replayed from an unauthorized client IP. |

### Generating Synthetic Datasets

Regenerate all canonical datasets using a deterministic random seed:
```bash
python scripts/generate_datasets.py --seed 42 --output-dir data/synthetic
```
Or via the simulator CLI:
```bash
python -m simulator --generate-datasets --seed 42
```

### Running and Streaming Scenarios

1. **Print scenario events to the console**:
   ```bash
   python -m simulator --scenario refresh-reuse --pretty
   ```

2. **Stream scenario events directly to a running Event Collector**:
   ```bash
   python -m simulator --scenario refresh-reuse --collector-url http://127.0.0.1:5000/events
   ```

3. **Submit Khushi's pre-generated datasets**:
   ```bash
   python scripts/submit_dataset.py
   ```

4. **Trigger scenarios via REST API**:
   ```bash
   curl -X POST http://127.0.0.1:5000/api/scenarios/refresh-reuse/run \
     -H "Authorization: Bearer tokenline-admin-secret"
   ```

---

## Actual Detector Behavior & Known Limitations

TokenLine's correlation engine implements 5 canonical anomaly detection rules:

| Rule ID | Name | Severity | Trigger Condition | Engine Action |
| :--- | :--- | :--- | :--- | :--- |
| `TL-RULE-001`<br>`(RULE-TOKEN-REUSE)` | Refresh-Token Reuse | `critical` | Refresh request presents a `parent_token_hash` that has already been rotated (`is_rotated=True`). | Marks token as `REUSED`, revokes entire token family, logs `TokenReuseRecord` and creates deduplicated `AlertRecord`. Recognizes historical replay of prior rotations without false alerting. |
| `TL-RULE-002`<br>`(RULE-REVOKED-USE)` | Post-Revocation Use | `high` | Token presentation occurs on a token marked `REVOKED` (e.g. post-logout or post-family cascade). | Logs `revoked_token_use` detection record and alert. Accounts for out-of-order delivery timestamps. |
| `TL-RULE-003`<br>`(RULE-EXPIRED-USE)` | Post-Expiration Use | `high` | Token presentation occurs on a token marked `EXPIRED` (past recorded expiry timestamp). | Logs `expired_token_use` detection record and alert. |
| `TL-RULE-004`<br>`(RULE-CONCURRENT-USE)` | Concurrent Use Anomaly | `high` | Same token used across distinct `device_id` or `ip_hash` values within $\Delta t \le 60\text{s}$. | Logs `concurrent_use` detection record and alert. Same-device/same-IP concurrent requests are classified as legitimate. |
| `TL-RULE-005`<br>`(RULE-IMPOSSIBLE-TRAVEL)`| Impossible Travel | `high` | Same user or token observed in distinct countries within $\Delta t \le 300\text{s}$ (5 minutes). | Logs `impossible_travel` detection record and alert. |

### Evaluation Metrics Framework

The evaluator ([`backend/correlator/evaluator.py`](backend/correlator/evaluator.py)) provides standard incident-level benchmark calculations:
- True Positives ($TP$), False Positives ($FP$), True Negatives ($TN$), False Negatives ($FN$)
- $\text{Precision} = \frac{TP}{TP + FP}$
- $\text{Recall} = \frac{TP}{TP + FN}$
- $\text{Specificity} = \frac{TN}{TN + FP}$
- $\text{F1-Score} = \frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$
- Explicit representation for zero-denominator edge cases (rendered as `None` / `N/A`, never invented).

### Known Limitations & Reality Boundaries

> [!WARNING]
> **Risk Signals, Not Proof of Compromise**: Detections produced by TokenLine indicate anomalous behavioral risk, **not** definitive proof of malicious compromise. Real-world systems exhibit non-adversarial anomalies:
> 
> - **VPN & Proxy Switching**: When a legitimate user connects to or disconnects from a VPN, their public IP and country will jump instantaneously, triggering `RULE-IMPOSSIBLE-TRAVEL`.
> - **Mobile Network Handoff**: A smartphone switching from cellular LTE to local Wi-Fi changes IP addresses while performing concurrent background API calls, which can trigger `RULE-CONCURRENT-USE`.
> - **Coarse Geolocation**: TokenLine's impossible-travel check currently operates on ISO country codes and time thresholds, rather than Haversine spherical flight speed calculations or ISP BGP/ASN telemetry.
> - **Process State Lifetime**: In-memory sliding windows for concurrent use and velocity analysis reset if the collector process restarts without state warm-up.
> - **Synthetic Scenarios are Not Production Proof**: Passing synthetic benchmark scenarios proves that the correlation engine's logic behaves as designed under controlled inputs. It does **not** prove resilience against sophisticated adversaries in production environments (e.g. distributed evasion, clock manipulation, token-binding circumvention).
> - **Unimplemented Research Features**: Concepts mentioned in exploratory research docs—such as automated session fixation analysis, continuous risk decay scoring, and automated browser fingerprint evaluation—are research concepts, not implemented features in `engine.py`.

---

## Live Versus Mock Frontend Modes

The repository contains two frontend user interfaces, both designed to function reliably whether connected to a live backend or viewed in standalone offline mode:

### 1. Interactive Single-Page Application (`frontend/index.html`)

- **Live Mode**: When loaded from the running collector (`http://127.0.0.1:5000`), the client service ([`frontend/js/data.js`](frontend/js/data.js)) automatically queries the collector API endpoints:
  - `GET /api/events?limit=100` — live ingested events
  - `GET /api/families` — correlated token family memberships
  - `GET /api/families/<id>` — lineage chains
  - `POST /api/scenarios/<id>/run` — on-demand scenario execution
- **Offline / Mock Fallback**: If the backend is unreachable or returns empty data, `TokenDataService` automatically and silently falls back to pre-bundled scenario fixtures (`INITIAL_EVENTS` and `INITIAL_FAMILIES`). This allows developers to demonstrate the UI, the dynamic SVG tree diagram, and the 3D globe without running the backend.

### 2. Operational Dashboard (`frontend/dashboard/index.html`)

- **Live Fetching**: Configured in [`frontend/dashboard/app.js`](frontend/dashboard/app.js) to query `http://127.0.0.1:5000/events`.
- **Mock Fallback**: If the fetch fails due to network or CORS errors, it catches the exception and falls back to an internal mock data array, rendering warning details in the browser console.

---

## Privacy, Retention, & Local-Only Safety Boundaries

TokenLine enforces strict zero-trust credential rules designed to protect systems from credential leakage:

### 1. Three-Layer Credential Sanitization

Before any event is persisted or passed to the correlator, `backend/collector/app.py` passes the payload through three validation layers:

1. **Structural Hash Validation**: Ensures that fields designated for hashes conform strictly to expected hash patterns (`[0-9a-fA-F]{12,64}` or `hash_[0-9a-fA-F]{12}`).
2. **Pattern Scanning**: Recursively scans all strings, object keys, and arrays for raw JWTs (`ey...`), Authorization credential schemes (`Bearer ...`, `Basic ...`), and key-value credential assignments.
3. **Shannon Entropy Analysis**: Analyzes high-entropy string chunks ($\ge 20$ chars, mixed character classes, Shannon entropy $\ge 4.0$). Suspicious tokens that could bypass regexes are flagged and rejected with HTTP 400 Bad Request.

### 2. Privacy-Preserving HMAC Token Identification

- Real tokens, session cookies, and passwords must **never** be stored or transmitted to TokenLine.
- The demo app hashes tokens using `crypto.createHmac('sha256', TOKEN_HMAC_SECRET)` before emitting events.
- The collector only ever handles salted, one-way hashes (`token_hash`).
- *Limitation*: The security of this mechanism depends on the secrecy of `TOKEN_HMAC_SECRET`. Rotating this secret invalidates correlation with prior event records.

### 3. Data Retention & Storage Scope

- **Local Storage Artifact**: In local development, all data resides in the local SQLite database file `tokenline.db`. Deleting or recreating this file immediately wipes all stored history.
- **Hosted PostgreSQL (Neon)**: Can be cleared via database migrations or table truncates.
- **Synthetic Data Exclusivity**: TokenLine is designed exclusively for synthetic, simulated, or controlled demonstration data. Connecting real user accounts, production credentials, or live identity providers is strictly prohibited.
- **Zero External Network Egress**: The attack simulator and scenario generators operate entirely on localhost. No packets are transmitted to external networks during attack simulation.

---

## Repository Structure

```text
TokenLine/
├── README.md                 # Primary project overview, setup guide, and documentation
├── PROJECT_FLOW.md           # End-to-end data flow, table models, and lifecycle diagram
├── PROJECT_TRAINING_GUIDE.md # Onboarding, mental model, and technical deep-dive
├── requirements.txt          # Python dependencies (Flask, SQLAlchemy, jsonschema, pytest)
├── pytest.ini                # Pytest configuration
├── .env.example              # Sample environment configuration for the Python collector
│
├── schema/
│   ├── event.schema.json     # Strict canonical JSON Schema contract
│   └── PROPOSED_CHANGES.md   # Schema evolution log
│
├── backend/
│   ├── collector/            # Event Collector HTTP server
│   │   ├── app.py            # Flask REST API, 3-layer sanitizer, RBAC authorization
│   │   └── db.py             # SQLAlchemy database models & timezone normalization
│   ├── correlator/           # Unified Token Family Correlation & Detection Engine
│   │   ├── engine.py         # TokenFamilyCorrelator state machine & lineage builder
│   │   ├── models.py         # In-memory domain models (TokenRecord, AlertRecord)
│   │   ├── evaluator.py      # Benchmark evaluation framework (TP, FP, Precision, F1)
│   │   └── README.md         # Component-level correlator documentation
│   └── database/             # Database migration system
│       └── migrations.py     # Schema migrations (001_initial through 006_alerts_table)
│
├── demo-app/                 # Standalone Node.js/Express demo authentication service
│   ├── src/                  # Routes, middleware, HMAC token service, event emitter
│   ├── tests/                # Jest integration test suite
│   ├── package.json          # Node dependencies & test scripts
│   ├── .env.example          # Sample environment configuration for demo app
│   └── README.md             # Component-level demo app documentation
│
├── simulator/                # Deterministic synthetic attack generator
│   ├── runner.py             # CLI runner and HTTP scenario dispatcher
│   ├── base.py               # Base scenario generator with seed control
│   ├── evaluation_datasets.py# Benchmark incident datasets for evaluation
│   ├── normal/               # Benign session lifecycle generator
│   ├── refresh-reuse/        # Refresh-token reuse attack generator
│   ├── expired-token/        # Expired token presentation generator
│   ├── revoked-token/        # Use after logout generator
│   ├── concurrent-use/       # Concurrent device anomaly generator
│   ├── impossible-travel/    # Regional velocity anomaly generator
│   ├── replay/               # Token replay attack generator
│   └── README.md             # Component-level simulator documentation
│
├── frontend/                 # Static security investigation interface
│   ├── index.html            # Main single-page application
│   ├── js/                   # SPA routing, SVG lineage diagrams, 3D canvas globe
│   ├── css/                  # Dark-mode design system & tokens (tokens.css, main.css)
│   └── dashboard/            # Operational metrics dashboard shell
│
├── data/
│   └── synthetic/            # Canonical pre-generated scenario JSON datasets
│
├── scripts/
│   ├── generate_datasets.py  # Dataset generator CLI script
│   └── submit_dataset.py     # Script to stream datasets to collector
│
├── docs/                     # Architecture, threat models, detection rules, research
└── tests/                    # Automated Pytest suite (unit & scenario tests)
```

---

## Resources & Standards

### Specifications & Security Guidance
- [RFC 7519 — JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 6819 — OAuth 2.0 Threat Model and Security Considerations](https://www.rfc-editor.org/rfc/rfc6819)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [MITRE ATT&CK T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK T1550 — Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)

### Supporting Research Documents
- [`Research_Doc/Reeva.md`](Research_Doc/Reeva.md) — Architecture, safety, and evaluation research.
- [`Research_Doc/Urval.md`](Research_Doc/Urval.md) — Market analysis and open-source forensic tools.
- [`Research_Doc/Khushi.md`](Research_Doc/Khushi.md) — Commercial IdPs and detection engines.
