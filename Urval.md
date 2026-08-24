# Existing Project & Similar Solution Research — TokenLine

**Contributor:** Urval Kheni
**Branch:** urval
**Related Issue:** Research Phase — Market & Prior-Art Validation
**Status:** ✅ Completed
**Research Date:** August 2026


---

## 1. Objective

To independently verify whether a project functionally equivalent to **TokenLine** — a tool that reconstructs the full lifecycle of an individual authentication token (issuance → usage → refresh → revocation/expiry) into one investigable timeline, with built-in anomaly detection — already exists, using a different research trail than prior team research (vendor docs only). This document draws on:

* Current (2026) CIAM/identity-risk product landscape
* Open-source GitHub repositories solving *adjacent* problems
* Academic/peer-reviewed digital forensics research
* Live GitHub issues from real OAuth/auth libraries, showing how far framework-level token-reuse detection actually goes

---

## 2. Method

Searches were run across web, GitHub, and research-paper indexes for terms including: token lifecycle visualization, session token forensic timeline, refresh token reuse/rotation detection, impossible travel detection tools, JWT security analyzers, and CIAM risk platforms (2026). A direct search for a project literally named "TokenLine" returned no matching cybersecurity project — only unrelated repos using "token" and "line" as generic naming (token parsers, PATs, etc.), confirming the name and concept are not already taken.

---

## 3. Newest Commercial / Identity-Risk Layer Products (2026)

These are risk/session-analytics add-ons that sit closer to TokenLine's problem space than classic IAM platforms, and were not covered in the earlier research pass.

### 3.1 WorkOS Radar

A detection layer built on top of WorkOS AuthKit that ingests signals from every authentication event and runs them through a rules/anomaly engine to flag abusive or anomalous behavior, including impossible-travel-style checks comparing login location/time pairs.

**Similarity to TokenLine:** Real-time anomaly signal generation from auth events; impossible travel logic.
**Gap vs TokenLine:** Radar scores individual *authentication events*, not the full lifecycle of one *token object* (issuance → refresh chain → revocation). There is no per-token timeline a human can open and read as a story; it is signal/alerting-oriented, not investigation/visualization-oriented.

### 3.2 Descope, Frontegg, Stytch (2026 CIAM landscape)

Current comparative reviews of the CIAM space list Descope, Auth0, Cognito, Entra External ID, Keycloak, Firebase, WorkOS, Stytch, and Frontegg as the leading platforms for 2026, with Descope highlighted for "risk-based authentication" and native AI-agent identity, and Frontegg for its self-service admin portal and audit history view.

**Similarity to TokenLine:** Risk-based auth decisions, audit-log surfaces, self-service session/device management.
**Gap vs TokenLine:** Audit history in these tools is a flat, filterable log — not a reconstructed per-token journey with parent/child refresh-token linkage or attack-pattern overlays (replay, concurrent-use, revoked-token-reuse) rendered on a single timeline.

### 3.3 Obsidian Security / BeyondTrust session-hijacking research

Both vendors published 2026 research proposing **behavioral, data-science-driven** session-hijacking detection (analyzing IP, ASN, user-agent, and device-fingerprint drift across a session using audit-log fields such as SessionID and ClientIP) as an evolution beyond simple rule-based impossible-travel detection.

**Similarity to TokenLine:** Session/token-centric anomaly modeling, use of the same underlying signal set (IP, ASN, UA, device) that TokenLine intends to use for concurrent-use and travel detection.
**Gap vs TokenLine:** These are internal research write-ups / blog-published methodologies, not shipped, general-purpose, self-hostable tools — and again they score sessions/events, not present an interactive lifecycle timeline end users can explore.

---

## 4. Open-Source Repositories Actually Touching This Space

This is the section most different from the earlier research pass, which focused on large IAM/SIEM platforms. Below are smaller, more directly comparable open-source projects found via targeted GitHub search.

| Project | What it actually does | Distance from TokenLine |
|---|---|---|
| **jwt-security-analyzer** (bavamont) | Desktop app (Electron) for decoding/encoding JWTs, validating signatures, and running ~22 attack-vector/vulnerability checks against a token. | Analyzes a *single token in isolation* at a point in time — no lifecycle, no cross-service correlation, no timeline. |
| **better-auth** OAuth 2.1 provider (GitHub issue #8512) | Implements refresh-token rotation with automatic **family-wide revocation** the moment a rotated/old refresh token is reused (a real, shipped reuse-detection mechanism). | Reuse detection exists, but only as an in-process security control (revoke & error) — there's no investigator-facing view of *why* it fired or the token's history leading up to it. |
| **django-oauth-toolkit** (GitHub issue #1404) | Open feature request to add RFC-aligned refresh-token reuse detection with token-family invalidation. | Confirms that even a widely used open-source OAuth toolkit does **not yet ship** reuse detection by default — it's still a requested feature, not existing functionality, let alone a visualized one. |
| **abdullah-ch/refresh-token-rotation** | Educational MERN-stack reference implementation of rotation + reuse detection. | Demonstrates the *mechanism* TokenLine would monitor, but is a teaching example, not an investigation/monitoring tool. |
| **SHVE – Session Hijacking Visual Exploitation** (Doyensec) | Offensive/red-team tool that hijacks and visually proxies a victim's live browser session via XSS. | Adjacent domain (attack simulation) but opposite direction: it *performs* hijacking rather than *detecting or reconstructing* it. Relevant to TokenLine's "Attack Simulation" feature as a reference implementation pattern, not a competing product. |

**Key finding:** Reuse/rotation detection logic *exists* scattered across individual auth libraries (better-auth, django-oauth-toolkit, Auth0's own reuse-detection docs), but it is implemented purely as an inline security control (silently revoke and reject) — never exposed as a browsable, human-readable timeline or investigation surface. This is a more precise, code-level confirmation of the gap TokenLine targets, versus only comparing against whole platforms.

---

## 5. Academic / Peer-Reviewed Grounding

To make sure "no one has built this" isn't just a marketing-page impression, the research also checked digital-forensics literature for prior art on timeline reconstruction and token/session anomaly detection.

* **"SoK: Timeline based event reconstruction for digital forensics"** (ScienceDirect, 2025) — a systematization-of-knowledge paper that formalizes terminology and methodology for reconstructing event timelines from logs for forensic investigation, and explicitly calls out the lack of a unified framework and open research gaps in this area. This supports TokenLine's core premise (that timeline reconstruction is a recognized but still-immature discipline) from an academic angle rather than a vendor one.
* **"Anomaly detection in a forensic timeline with deep autoencoders"** (Journal of Information Security and Applications) — proposes using deep autoencoders to flag anomalous events directly on a forensic timeline built from log entries, reporting strong detection accuracy. Conceptually close to TokenLine's anomaly-detection layer, but applied to generic OS/log timelines, not specifically to authentication-token lifecycles.
* **LSTM + Isolation Forest hybrid model for adaptive authentication risk scoring** (IJNRD, 2025) — a model that scores authentication risk in real time and decides whether to continue a session with a JWT or force step-up MFA, learned from historical authentication behavior. Relevant to TokenLine's anomaly-detection ambitions but scoped to the login decision, not to full post-issuance token tracking.
* **TryHackMe "Session Forensics" training room** (2025) — a hands-on cybersecurity training module teaching analysts to investigate compromised sessions/JWTs across application, web-server, and identity-provider logs, including tracing forged or replayed tokens. This confirms session/token forensic investigation is recognized as a distinct, teachable skill set industry-wide — but as *manual analyst technique*, not as packaged, automated tooling. It is effectively the workflow TokenLine aims to automate and visualize.

**Conclusion of this section:** The literature validates that (a) timeline-based reconstruction and (b) token/session anomaly detection are each independently active research areas, but no source found combines them into one token-centric, purpose-built, visual investigation product — reinforcing rather than duplicating the earlier finding.

---

## 6. Updated Feature Comparison

Extending the earlier comparison table with the newer products found in this pass:

| Feature | Okta/Entra/Auth0/Splunk (prior research) | WorkOS Radar / Descope / Frontegg (2026) | OSS libraries (better-auth, django-oauth-toolkit, jwt-security-analyzer) | Academic tools (autoencoder timeline, LSTM/IF) | **TokenLine** |
|---|:---:|:---:|:---:|:---:|:---:|
| Issues/manages tokens | ✅ | ✅ | ✅ | ❌ | ✅ |
| Per-event risk scoring | Partial | ✅ | ❌ | ✅ | ✅ |
| Refresh-token reuse detection | Partial | ❌ (not documented) | ✅ (inline, silent) | ❌ | ✅ (visualized) |
| Single-token lifecycle timeline (issue→use→refresh→revoke) | ❌ | ❌ | ❌ | Partial (generic events only) | ✅ |
| Parent–child refresh-token chain view | ❌ | ❌ | ❌ | ❌ | ✅ |
| Impossible travel / concurrent-use detection | Partial | ✅ | ❌ | ❌ | ✅ |
| Attack simulation (replay, fixation, theft) | ❌ | ❌ | Partial (SHVE, offensive only) | ❌ | ✅ |
| Self-hostable / open | Mostly ❌ | ❌ | ✅ | Research-only | ✅ (planned) |
| Unified investigator dashboard | ❌ | Partial (log view) | ❌ | ❌ | ✅ |

---

## 7. Findings

1. **No product or repository named or functionally equivalent to TokenLine exists.** A direct search for "TokenLine" surfaces only unrelated repositories.
2. The **2026 CIAM/risk layer** (WorkOS Radar, Descope, Frontegg) has moved toward real-time behavioral risk scoring of authentication *events*, but none render a **per-token lifecycle timeline**.
3. **Refresh-token reuse/rotation detection is a known, partially-solved problem at the framework level** (better-auth ships it; django-oauth-toolkit has an open request for it), but it is implemented as a silent inline security control, never as an investigator-facing visualization — this is a sharper, code-level version of the gap TokenLine addresses.
4. **Academic research treats timeline reconstruction and session/token anomaly detection as two separate, still-maturing subfields**; nothing in the literature merges them into one token-centric tool.
5. **Session/token forensics is recognized as a distinct manual-analyst skill** (per TryHackMe's dedicated training room), which is strong external validation that the workflow TokenLine automates is real, current, and not yet tool-assisted.

---

## 8. Conclusion

This independent research pass — using different sources (2026-era risk products, live OSS issue trackers, and peer-reviewed forensics literature) rather than a vendor-by-vendor feature comparison — reaches the **same conclusion as the earlier team research, but with stronger and more current evidence**: no existing commercial product, open-source repository, or published academic system reconstructs the full lifecycle of an individual authentication token into a single, interactive, anomaly-annotated timeline. TokenLine's specific combination — per-token storytelling, parent/child refresh-token graphs, and built-in attack simulation — remains unaddressed by the market as of August 2026.

---

## 9. References

**2026 Products / Vendor Analysis**
* WorkOS — "Impossible travel: what it is, how it works, and how to defend against it" (workos.com/blog/impossible-travel)
* Descope — "Best CIAM Solutions for 2026: 9 Platforms Compared" (descope.com/blog/post/ciam-solutions)
* Obsidian Security — "Session Hijacking: How It Works & How to Stop It" (obsidiansecurity.com/blog/session-hijacking-how-it-works-how-to-stop-it)
* BeyondTrust — "Session Hijacking Detection: A Data Science Approach" (beyondtrust.com/blog/entry/how-to-detect-session-hijacking)
* Obsidian Security — "Refresh Token Security: Best Practices for OAuth Token Protection" (obsidiansecurity.com/blog/refresh-token-security-best-practices)
* Auth0 — "Refresh Token Security: Detecting Hijacking and Misuse with Auth0" (auth0.com/blog)

**Open-Source Repositories**
* bavamont/jwt-security-analyzer — github.com/bavamont/jwt-security-analyzer
* better-auth/better-auth, Issue #8512 — github.com/better-auth/better-auth/issues/8512
* django-oauth/django-oauth-toolkit, Issue #1404 — github.com/django-oauth/django-oauth-toolkit/issues/1404
* abdullah-ch/refresh-token-rotation — github.com/abdullah-ch/refresh-token-rotation
* Doyensec — "Introducing Session Hijacking Visual Exploitation (SHVE)" — blog.doyensec.com

**Academic / Research**
* "SoK: Timeline based event reconstruction for digital forensics: Terminology, methodology, and current challenges," ScienceDirect, 2025
* "Anomaly detection in a forensic timeline with deep autoencoders," Journal of Information Security and Applications, ScienceDirect
* "User Behavior Analysis Using Machine Learning for [Adaptive Authentication]," IJNRD, 2025 (ijnrd.org)
* TryHackMe — "Session Forensics" room (via sharonjebitok.com/session-forensics-tryhackme)

**Standards (carried over / re-verified)**
* RFC 7519 – JSON Web Token (JWT)
* RFC 6749 – OAuth 2.0 Authorization Framework
* RFC 6819 – OAuth 2.0 Threat Model and Security Considerations
* OAuth 2.0 Security Best Current Practice, §4.14 (Refresh Token Reuse Detection)
* MITRE ATT&CK T1539 (Steal Web Session Cookie) & T1550 (Use Alternate Authentication Material)
