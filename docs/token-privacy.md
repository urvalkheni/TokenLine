# TokenLine Privacy-Preserving Token Identification

This document explains the security and privacy model used by TokenLine to identify and correlate authentication tokens without persisting or exposing sensitive credentials.

## 1. Why TokenLine Cannot Store Raw Tokens

Storing raw access tokens or refresh tokens presents a significant security risk. If the database or event logs were ever compromised, an attacker would gain immediate access to active session credentials, allowing them to impersonate users and bypass primary authentication. Since TokenLine is designed to monitor tokens, it must do so without becoming a target for credential theft.

## 2. Why Keyed HMAC is Used

To uniquely identify a token without storing its raw value, TokenLine uses a keyed HMAC (Hash-based Message Authentication Code), specifically `HMAC-SHA-256`. 

We use a keyed HMAC instead of a simple unkeyed cryptographic hash (like plain SHA-256) because plain hashes are susceptible to rainbow table attacks and brute-forcing. Since some tokens (like short access tokens) might lack sufficient entropy, an attacker with a database of hashes could attempt to guess or pre-compute the tokens. The use of a secret key ensures that the resulting identifier cannot function as a simple public hash; an attacker cannot generate or verify identifiers without possessing the secret key.

## 3. How Identifiers are Used for Correlation

The resulting canonical field stored in the event schema is:

`token_hash`

Events containing the same token will produce the same identifier (assuming the same secret key is used). This allows TokenLine to group, monitor, and correlate different events—such as `token_issued`, `token_used`, and `token_refreshed`—that refer to the same logical credential, entirely without storing the credential itself.

## 4. How Repeated Token Usage is Recognized

The HMAC function is deterministic:
`same token + same secret -> same token_hash`

When a user logs in, a `token_hash` is generated and logged in a `token_issued` event. When the user later refreshes their session using the same token, the exact same `token_hash` is generated and logged in a `token_refreshed` event. This consistency allows the correlation engine to recognize the token's lifecycle and detect anomalies (like refresh token reuse) across multiple events.

## 5. What Must Never Be Logged

To maintain this security model, the following sensitive data must **never** appear in application logs, database records, error messages, or JSON event files:
- Raw access tokens
- Raw refresh tokens
- `Authorization` headers containing tokens
- Cookies containing authentication tokens
- The HMAC secret/key (`TOKEN_HMAC_SECRET`)
- User credentials (e.g., passwords) or other authentication secrets

## 6. Limitations and Assumptions

- **Security of the Secret:** The security of this privacy mechanism depends entirely on the secure management of the `TOKEN_HMAC_SECRET` environment variable. If the secret is leaked, the protection degrades to that of a plain hash.
- **Key Rotation Impacts Correlation:** Changing the HMAC secret changes all generated identifiers. This means that correlation across old and new records will break when the key is rotated.
- **Scope of Correlation:** Deterministic identifiers allow correlation of repeated token use only within the scope of the same key.
- **Not Reversible:** `token_hash` is an opaque identifier, not a reversible encryption mechanism. TokenLine cannot decrypt the hash to recover the token.
- **Possession Required:** Generating a matching identifier requires possession of the original token.
- **State Management:** Token rotation, expiration, and revocation enforcement still depend on the surrounding TokenLine event and correlation model.
