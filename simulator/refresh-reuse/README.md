# Refresh-Token Reuse Attack Simulation

## Overview
Simulates token rotation where a root token `token_hash_a` is refreshed into `token_hash_b`. Subsequently, an attacker attempts to present the already-rotated `token_hash_a` to request another refresh token.

## Event Sequence
1. `token_issued`: Initial Token A issued to user on login (accepted).
2. `token_used`: User performs normal operations with Token A (accepted).
3. `token_refreshed`: User rotates Token A to Token B (`parent_token_hash` = Token A, accepted).
4. `token_used`: User performs operations with active Token B (accepted).
5. `token_refreshed`: Adversary attempts to refresh with rotated Token A (`parent_token_hash` = Token A, rejected).

## Correlator Integration
The Token-Family Correlator identifies that Token A is marked `rotated` and records a structured `TokenReuseRecord`.

## How to Run
```bash
python -m simulator --scenario refresh-reuse
```
