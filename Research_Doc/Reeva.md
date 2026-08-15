# TokenLine: Existing Solutions and Project Research

## 1. Executive Summary

TokenLine is a proposed cybersecurity tool that reconstructs the complete life story of an authentication token. It connects token events—issue, use, refresh, logout, revocation, and expiry—into one chronological timeline instead of showing them as unrelated log records.

The idea is useful, but it is not completely new. Large identity platforms and security products already detect parts of this problem. TokenLine can still be a valuable academic project because it focuses on a simple, visual, developer-friendly view of one token's complete lifecycle, including safe attack simulations.

## 2. What Already Exists?

### Identity-provider security products

Microsoft Entra ID Protection detects anomalous tokens, including tokens used from an unfamiliar location or with unusual characteristics. Microsoft describes this as a possible sign of token replay.

Okta Identity Threat Protection raises session risk when active-session activity matches patterns of session hijacking, token theft, or token replay. These products are powerful, but they are mainly designed for enterprise identity environments and may be difficult for a student to deploy.

### SIEM and log-analysis platforms

SIEM platforms collect authentication logs from many systems and create alerts. Teams can write rules to detect the same session being used from different IP addresses, devices, or locations. The limitation is that a SIEM usually depends on correct log collection and correlation rules. TokenLine's focused contribution is to group related events into one token-centered lifecycle.

### JWT inspection tools

Existing tools decode or compare JWT headers and claims. Some display `iat`, `nbf`, and `exp` values on a timeline. These tools are useful for inspecting a token, but normally do not monitor live usage, refresh history, logout, revocation, device changes, or replay attempts.

### Authentication servers

Platforms such as Keycloak and OAuth/OIDC implementations already support token validation, expiration, refresh, and revocation-related functions. Refresh-token rotation is important: after a refresh token is used, a new token is issued, and reuse of the old token can indicate replay.

TokenLine would not replace an identity provider. It would act as a monitoring, correlation, visualization, and educational analysis layer.

## 3. Existing Features vs. TokenLine

| Capability | Existing products/tools | Proposed TokenLine focus |
|---|---|---|
| JWT decoding | Common in developer tools | Optional safe inspection of claims |
| Expiry checking | JWT libraries and identity providers | Show expiry as part of the full timeline |
| Token refresh | OAuth/OIDC servers | Connect the old token to its successor |
| Revocation | Identity providers and application servers | Show when and why revocation happened |
| Session logging | OWASP recommends lifecycle logging | Provide one token-centered event history |
| Replay detection | Entra, Okta, and custom SIEM rules | Explain the evidence on the timeline |
| Impossible travel | Enterprise identity products and SIEM rules | Demonstrate it with controlled test data |
| Attack simulation | Separate security labs and test tools | Include safe, local demonstrations |
| Visualization | Dashboards and log viewers | Make one token's life story the main view |

## 4. Why TokenLine Is Still a Good Project

TokenLine should not claim to be the first system to detect token theft or replay. Its originality can be presented as the combination of these features in one small, understandable platform:

- A token-lifecycle graph connecting issuance, use, refresh, and termination.
- A timeline that explains why an event is normal or suspicious.
- A privacy-preserving token identity, such as a salted hash, instead of storing raw tokens.
- A replay and concurrent-use simulator for a local test environment.
- Simple anomaly rules that students and developers can understand and verify.
- Exportable evidence for security analysis and classroom demonstrations.

**Recommended project claim:** TokenLine is an educational and developer-focused token lifecycle correlation and visualization system, not a replacement for enterprise identity protection products.

## 5. Recommended Project Scope

### Minimum viable product

1. Create a demo application with login, logout, access tokens, and refresh tokens.
2. Send only safe event metadata: event time, event type, user ID, token hash, IP address, user-agent summary, device ID, endpoint, and result.
3. Store events in a database and group them by token hash and token family.
4. Display a chronological timeline for each token.
5. Implement alerts for expired-token use, revoked-token use, refresh-token reuse, concurrent locations, and impossible travel.
6. Provide a dashboard with severity, reason, evidence, and recommended response.

### Future scope

- Support cookie sessions and JWTs through a common event format.
- Add integrations for Keycloak, Auth0, Okta, or a SIEM.
- Add analyst comments, alert status, and incident export.
- Add configurable time and distance thresholds.
- Compare activity with the user's normal device and location pattern.

## 6. Proposed Architecture

```text
Demo application / identity provider
              |
              v
     TokenLine event collector
              |
              v
  Normalizer + token-family correlator
              |
              +--> Rule-based anomaly engine
              |
              v
   Database --> REST API --> Web dashboard
```

A normalized event could contain:

```json
{
  "event_id": "evt-1001",
  "event_type": "token_used",
  "time": "2026-08-07T12:20:00Z",
  "user_id": "user-42",
  "token_hash": "salted-hmac-value",
  "token_family": "family-8",
  "ip_hash": "privacy-preserving-value",
  "country": "IN",
  "device_id": "device-2",
  "user_agent_family": "Chrome",
  "endpoint": "/api/profile",
  "result": "accepted"
}
```

The system must never collect real production tokens for a classroom demonstration. It should use generated tokens and synthetic data, or store only a keyed HMAC/hash that cannot be used as a credential. OWASP recommends recording session lifecycle events while avoiding raw session IDs in logs.

## 7. Detection Rules

| Rule | Example condition | Severity |
|---|---|---|
| Expired use | A token is accepted after its expiry time | High |
| Revoked use | A revoked token is presented again | High |
| Refresh replay | An already-used rotated refresh token is used again | Critical |
| Concurrent use | One token is used from two distant devices within a short time | High |
| Impossible travel | The user appears in locations that cannot be reached in the available time | High |
| Long session | A session remains active beyond configured policy | Medium |
| Session fixation signal | The same session identifier continues across authentication or privilege change | High |

These are detection signals, not automatic proof of an attack. VPNs, mobile networks, proxies, shared computers, and inaccurate geolocation can create false positives. The dashboard should show the evidence and allow an analyst to mark an alert as confirmed, dismissed, or requiring investigation.

JWT's `exp` claim identifies when a token must no longer be accepted, while `iat` records when it was issued. These claims can help calculate token age and validity, but the application must also validate the signature, issuer, audience, and other policy requirements.

## 8. Attack Simulation Plan

All demonstrations must run only on a local application or isolated lab environment:

- **Token theft:** copy a generated test token to a second simulated client and show a device-context change.
- **Replay:** send the same test token again after it has already been used or rotated.
- **Use after logout:** log out, then present the test token and record the rejection.
- **Refresh-token misuse:** use an old refresh token after a new one has been issued.
- **Session fixation:** show a session identifier that is not regenerated after login, then show secure behavior.
- **Impossible travel:** generate synthetic events from distant locations with an unrealistic time gap.

The project should not include instructions for stealing tokens from real users, bypassing authentication, or attacking public systems. All credentials, users, locations, and tokens should be fictional.

## 9. Technical and Ethical Risks

- **Raw-token exposure:** Never place tokens in logs, screenshots, URLs, analytics, or error messages.
- **Privacy:** IP addresses, locations, user agents, and device information can be personal data. Hash or minimize them and define a retention period.
- **False positives:** Explain that anomaly rules show risk, not certainty.
- **Time problems:** Use UTC internally and handle clock skew carefully.
- **Correlation problems:** Use a stable event schema across systems.
- **Access control:** Only authorized analysts should view security events.
- **Dangerous testing:** Use mock data and an isolated lab, never live accounts.

## 10. Suggested Evaluation

The project can be evaluated with a test dataset containing normal and suspicious-looking scenarios:

- Can the system reconstruct every event in the correct order?
- Can it connect a refresh token to its successor?
- Does it detect expired, revoked, and replayed tokens?
- Does it identify suspicious location or device changes?
- Does it avoid storing raw credentials?
- Can a student understand the reason for every alert?
- How many false positives appear in normal scenarios?

Useful measurements include event-processing time, alert-generation time, timeline accuracy, detection rate on test cases, and false-positive rate.

## 11. Final Conclusion

The general security problem already exists in products such as Microsoft Entra ID Protection, Okta Identity Threat Protection, SIEM platforms, and authentication servers. JWT decoders and timeline utilities also cover small parts of the idea.

TokenLine remains a strong project if its contribution is stated honestly: it brings token lifecycle correlation, visual explanation, privacy-aware logging, and safe attack simulation together in a focused tool for learning and development. This makes the project practical, demonstrable, and different in presentation even though its underlying security concepts are established.

## 12. Resources

### Standards and security guidance

- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Current Practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)

### Existing products and research references

- [Microsoft Token Theft Playbook](https://learn.microsoft.com/en-us/security/operations/token-theft-playbook)
- [Microsoft Entra token protection guidance](https://learn.microsoft.com/en-us/entra/identity/devices/protecting-tokens-microsoft-entra-id)
- [Okta session-influenced user risk](https://help.okta.com/oie/en-us/content/topics/itp/detections-session-influenced.htm)
- [JWT Auditor comparison guide](https://jwtauditor.com/docs/jwt-tools-comparison.html)

## 13. AI Chats and Research Method

AI assistance was used to help organize the project idea, identify existing categories of solutions, simplify technical language, and prepare this research outline. The technical claims should be checked against the linked standards and official documentation before the final presentation.

Suggested disclosure:

> I used an AI assistant to support brainstorming, research organization, and language editing. I independently reviewed the linked standards and documentation, selected the project scope, and will implement and test the system myself.
