# TokenLine

> **Tracking the Life of a Login Session**

TokenLine is a planned developer-focused and educational authentication-token lifecycle correlation and visualization system. It reconstructs the life of authentication tokens and sessions from security events, then presents that history as an investigable timeline.

## Project status

**Current phase: Phase 0 — Research & Design (complete).**

The repository currently contains research and planning documents only. No application, collector, dashboard, event schema, or detection engine has been implemented yet. The architecture, MVP, and repository layout below are planned work, not descriptions of current functionality.

## The problem

Modern applications use authentication artifacts such as JWT access tokens, refresh tokens, session cookies, OAuth/OIDC tokens, and application sessions. An authentication system generally knows when an artifact is issued; it may also know when it expires or is revoked. During an investigation, however, the more useful question is:

> What happened to this authentication token throughout its entire lifetime?

For example:

```text
Login
  ↓
Access token issued
  ↓
Token used from Device A
  ↓
Token refreshed
  ↓
New token issued
  ↓
Old refresh token reused
  ↓
Suspicious activity detected
  ↓
Session revoked
```

Traditional authentication systems, SIEMs, and security dashboards often expose these as separate logs or alerts. TokenLine addresses the problem of reconstructing disconnected authentication events into one understandable token or session lifecycle, so an analyst can assess whether that lifecycle contains suspicious behavior.

## Inspiration and position

TokenLine is inspired by the gap between authentication systems that issue and manage tokens, SIEMs that collect security logs, security-testing tools that inspect or replay tokens, and analysts who must manually reconstruct what occurred.

Its central idea is simple: instead of investigating hundreds of authentication logs, an analyst should be able to select a token or session and see its entire life as a visual, evidence-backed story.

TokenLine is **not** intended to replace Okta, Microsoft Entra, Auth0, Keycloak, Splunk, Elastic Security, Wazuh, Burp Suite, or OWASP ZAP. It is a focused monitoring, correlation, visualization, and educational analysis layer.

## Research and existing solutions

The project research examined these related solution categories:

| Area | Examples examined |
| --- | --- |
| Commercial / identity security | Okta, Microsoft Entra ID Protection, Auth0, WorkOS Radar, Descope, Frontegg |
| SIEM / security monitoring | Splunk Enterprise Security, Elastic Security, Wazuh |
| Open source / developer security | Keycloak, SuperTokens, better-auth, django-oauth-toolkit, jwt-security-analyzer, OWASP ZAP, Burp Suite Community Edition |
| Research / forensics | Timeline-based digital forensics, forensic-timeline anomaly detection, adaptive authentication risk scoring, and session/token forensic investigation |

Existing solutions implement important parts of the problem, including authentication, session management, refresh-token reuse detection, risk scoring, log correlation, token inspection, and anomaly detection. TokenLine focuses on combining these concepts into a token-centric lifecycle investigation interface.

The project deliberately makes no “first” or exclusivity claim. Research indicates that related capabilities are distributed across identity products, security platforms, libraries, testing tools, and forensic research; product behavior and coverage should be verified against primary documentation before making comparative claims.

## The specific gap

Existing solutions commonly provide:

```text
Authentication
Session management
Risk scoring
Authentication logs
Token inspection
SIEM correlation
Attack testing
```

TokenLine’s planned contribution is a lifecycle view centered on the token itself:

```text
                    TOKEN
                      │
                      ▼
             ┌────────────────┐
             │ Token issued   │
             └───────┬────────┘
                     │
                     ▼
             ┌────────────────┐
             │ Token used     │
             └───────┬────────┘
                     │
                     ▼
             ┌────────────────┐
             │ Token refreshed│
             └───────┬────────┘
                     │
                     ▼
             ┌────────────────┐
             │ Child token    │
             └───────┬────────┘
                     │
                     ▼
             ┌────────────────┐
             │ Replay / abuse │
             └───────┬────────┘
                     │
                     ▼
             ┌────────────────┐
             │ Revoked/expired│
             └────────────────┘
```

The key contribution is **per-token lifecycle reconstruction, parent/child token relationships, explainable anomaly detection, and visual investigation**.

## Planned MVP

The initial target is to provide:

1. A demo authentication application.
2. Login and logout.
3. Access-token generation.
4. Refresh-token generation.
5. Authentication-event collection.
6. Privacy-preserving token identification.
7. Token-family correlation.
8. A chronological token timeline.
9. Token-usage tracking.
10. Token-expiry tracking.
11. Revocation tracking.
12. Refresh-token parent/child relationships.
13. Expired-token detection.
14. Revoked-token-use detection.
15. Refresh-token-reuse detection.
16. Concurrent-use detection.
17. Impossible-travel detection using controlled test data.
18. Explainable alerts.
19. A security-investigation dashboard.
20. Safe attack simulation using synthetic or local data.

Detection results are risk signals, not proof of compromise.

## Token lifecycle model

TokenLine will reconstruct a lifecycle such as:

```text
ISSUED
   ↓
USED
   ↓
REFRESHED
   ↓
SUCCESSOR ISSUED
   ↓
USED
   ↓
REVOKED / EXPIRED
```

Planned event names include:

- `token_issued`
- `token_used`
- `token_refreshed`
- `token_revoked`
- `token_expired`
- `logout`
- `refresh_reuse_detected`
- `suspicious_location`
- `suspicious_device`
- `replay_detected`

The actual, versioned event schema is future work and will be defined separately as the project develops.

## Token families

A refresh operation may create a successor in a related token family:

```text
Refresh Token A
      │
      └──── refresh ────> Refresh Token B
                              │
                              └──── refresh ────> Refresh Token C
```

TokenLine should distinguish an individual token identity, its token-family identity, its parent token, and its successor/child token. This permits an investigation to follow rotation and, where supported by the demo policy, family-wide revocation after refresh-token reuse. Raw credentials must not be stored merely to create these relationships.

## Privacy and security design

> TokenLine is designed for synthetic/local demonstrations and controlled test environments. It must never store real production authentication tokens.

Token identifiers should use a privacy-preserving representation, such as a salted hash or keyed HMAC. TokenLine must not log raw access tokens, raw refresh tokens, session cookies, or Authorization headers that contain credentials.

IP addresses, location, user-agent data, and device information can be sensitive. The planned system should minimize these fields, hash them where appropriate, and use controlled synthetic values whenever possible. Other design requirements include:

- Use UTC timestamps internally and account for clock skew in analysis.
- Define event-retention and deletion practices before collecting data.
- Limit event and dashboard access to authorized analysts.
- Explain uncertainty and false positives instead of treating an alert as certainty.
- Keep testing isolated and safe.

## Initial detection rules

| Detection | Example | Initial severity |
| --- | --- | --- |
| Expired token use | Token presented after expiration | High |
| Revoked token use | Revoked token presented again | High |
| Refresh-token reuse | Previously rotated refresh token reused | Critical |
| Concurrent use | Same token used from distant devices | High |
| Impossible travel | Locations/time physically impossible | High |
| Long session | Session exceeds configured policy | Medium |
| Session fixation signal | Session identifier survives authentication or privilege change | High |

These are **risk signals, not automatic proof of compromise**. VPNs, proxies, mobile networks, shared devices, inaccurate geolocation, and clock differences can produce false positives. Each alert should make its triggering evidence and rationale visible to an analyst.

## Planned architecture

```text
┌───────────────────────────────┐
│ Demo Application / IdP        │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ TokenLine Event Collector     │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ Event Normalizer              │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ Token / Family Correlator     │
└───────────────┬───────────────┘
                │
        ┌───────┴────────┐
        ▼                ▼
┌──────────────┐  ┌────────────────┐
│ Rule Engine  │  │ Token Timeline │
└──────┬───────┘  └───────┬────────┘
       │                  │
       └────────┬─────────┘
                ▼
       ┌─────────────────┐
       │ REST API        │
       └────────┬────────┘
                ▼
       ┌─────────────────┐
       │ Web Dashboard   │
       └─────────────────┘
```

No programming language, framework, database, or deployment platform has been selected in the current research. Those decisions must follow the event-schema, threat-model, and implementation design work.

## Planned repository structure

The following is a **planned architecture**, not the current folder structure:

```text
TokenLine/
├── README.md
├── Reeva.md
├── Urval.md
├── khushi.md
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── detection-rules.md
│   ├── event-schema.md
│   ├── attack-scenarios.md
│   └── research.md
│
├── backend/
│   ├── collector/
│   ├── correlator/
│   ├── detection/
│   ├── api/
│   └── database/
│
├── frontend/
│   ├── dashboard/
│   ├── timeline/
│   └── token-view/
│
├── simulator/
│   ├── replay/
│   ├── refresh-reuse/
│   ├── revoked-token/
│   └── impossible-travel/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── scenarios/
│
├── data/
│   └── synthetic/
│
├── scripts/
├── .agents/
├── .codex/
└── .git/
```

## Safe attack simulation

All simulations must use generated credentials, local applications, and isolated test environments.

| Scenario | Controlled demonstration |
| --- | --- |
| Token replay | Present a generated test token again and record the result. |
| Token theft simulation | Copy a synthetic test credential between two controlled simulated clients and observe a device-context change. |
| Use after logout | Log out, then attempt to use the test credential. |
| Refresh-token reuse | Use an old refresh token after rotation. |
| Session fixation | Demonstrate insecure session behavior locally and compare it with secure behavior. |
| Impossible travel | Generate synthetic events from distant locations with unrealistic time differences. |

**No real users, credentials, production tokens, or public systems may be attacked.** TokenLine is not a credential-theft tool, token-harvesting system, or third-party attack platform.

## Evaluation

TokenLine will be evaluated using synthetic normal and suspicious scenarios. Key questions are:

- Can it reconstruct events in the correct order?
- Can it connect refresh-token successors?
- Can it detect expired-token use, revoked-token use, and refresh-token reuse?
- Can it identify suspicious device or location changes?
- Does it avoid storing raw credentials?
- Can an analyst understand why an alert was generated?

Candidate metrics are timeline-reconstruction accuracy, detection rate, false-positive rate, event-processing latency, alert-generation latency, and correlation accuracy.

## Development roadmap

```text
Phase 0 — Research & Design
[Current: complete]
    ↓
Phase 1 — Event Schema
    ↓
Phase 2 — Demo Authentication System
    ↓
Phase 3 — Event Collector
    ↓
Phase 4 — Token Correlation
    ↓
Phase 5 — Lifecycle Timeline
    ↓
Phase 6 — Detection Engine
    ↓
Phase 7 — Attack Simulator
    ↓
Phase 8 — Dashboard
    ↓
Phase 9 — Testing & Evaluation
    ↓
Phase 10 — Documentation & Final Demo
```

Only Phase 0 is complete. All subsequent phases are future work.

## Scope boundaries

TokenLine is not:

- An identity provider.
- A replacement for OAuth/OIDC.
- A production SIEM.
- A credential-theft tool.
- A real-world token-harvesting system.
- Designed to attack third-party systems.
- A guarantee that a detected anomaly means compromise.

## Project philosophy

> **“Don't just show the alert. Show the story behind the alert.”**

The central user experience should answer: what token was involved; who used it; when it was issued; where and on which device it was used; whether it was refreshed; what token replaced it; whether it was revoked or reused; why activity appears suspicious; and what evidence supports the alert.

### Example investigation

```text
12:00  Login
       ↓
12:00  Access Token A issued
       ↓
12:05  Token A used — Device A / Ahmedabad
       ↓
12:30  Refresh Token A used
       ↓
12:30  Token B issued
       ↓
12:35  Token B used — Device A
       ↓
12:36  Refresh Token A reused
       ↓
       🚨 REFRESH TOKEN REUSE
       ↓
12:36  Token family revoked
```

TokenLine should present this as one investigation with connected evidence, rather than as unrelated log entries.

# AI Agent Development Guidelines

These rules apply to AI coding agents and contributors working in this repository.

## Before modifying code

1. Read `README.md`.
2. Read the relevant files under `docs/` when they exist.
3. Inspect the existing implementation.
4. Do not assume a feature exists.
5. Check the current architecture before introducing components.
6. Prefer small, testable changes.
7. Do not rewrite working components unnecessarily.

## Security rules

Never:

- Store raw authentication tokens.
- Log Authorization headers.
- Log refresh tokens.
- Generate instructions for attacking real systems.
- Use real credentials.
- Connect attack simulations to production systems.
- Weaken authentication for convenience.

Use synthetic users, synthetic tokens, isolated local environments, privacy-preserving identifiers, and deterministic test scenarios.

## Research rules

When making security claims:

1. Prefer RFCs.
2. Prefer OWASP documentation.
3. Prefer official vendor documentation for vendor-specific behavior.
4. Prefer peer-reviewed research for academic claims.
5. Clearly distinguish verified facts, project assumptions, implementation decisions, and future ideas.

Do not claim TokenLine is “the first” unless strong evidence supports that claim. Use this defensible wording instead:

> TokenLine focuses on combining token lifecycle correlation, visualization, explainable anomaly detection, and safe attack simulation into a focused educational and developer-oriented platform.

## AI agent resource hierarchy

When resolving project questions, use this order:

```text
1. README.md
       ↓
2. docs/
       ↓
3. Existing source code
       ↓
4. Tests
       ↓
5. Reeva.md / Urval.md / khushi.md
       ↓
6. Official standards and documentation
       ↓
7. External web research
```

For JWT, use [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519). For OAuth, use [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), and OAuth security best practices. For session management and logging, use the [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) and [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html). For token and session threats, use MITRE ATT&CK, OWASP, Microsoft security documentation, and official identity-provider documentation. For implementation behavior, prefer official repositories and documentation; consult GitHub issues or pull requests where behavior is under discussion.

Do not rely on random blogs when authoritative documentation is available.

## Resources

### Standards and security guidance

- [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 6749 — OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [MITRE ATT&CK T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK T1550 — Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)

### Project research

- [Reeva.md](Research_Doc/Reeva.md) — project research, architecture, safety, and evaluation outline.
- [Urval.md](Research_Doc/Urval.md) — market, open-source, and forensics research.
- [Khushi.md](Research_Doc/Khushi.md) — commercial and open-source solution research.

The research documents are supporting sources. This README is the project’s current source of truth; future decisions should be documented under `docs/` and reflected here when they change project-wide direction.
