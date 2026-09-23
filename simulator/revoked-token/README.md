# Use After Logout (Revoked Token) Attack Simulation

## Overview
Simulates session termination where a user logs in, performs actions, and explicitly logs out (or revokes their token). Following logout, an unauthorized party attempts to present the revoked token.

## Event Sequence
1. `token_issued`: User signs in from `device-workstation-01` (accepted).
2. `token_used`: Authorized query to `/api/v1/projects` (accepted).
3. `logout`: User terminates session via `/api/auth/logout` (accepted).
4. `token_used`: Post-logout request using the invalidated token (rejected).

## How to Run
```bash
python -m simulator --scenario revoked-token
```
