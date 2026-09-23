# Token Replay Attack Simulation

## Overview
Simulates an attack scenario where an adversary captures a legitimate access token and attempts to replay it against protected API endpoints from a foreign IP/device after legitimate requests have already occurred.

## Event Sequence
1. `token_issued`: User logs in legitimately from `device-legit-laptop` (accepted).
2. `token_used`: User queries `/api/v1/profile` (accepted).
3. `token_used`: User queries `/api/v1/dashboard` (accepted).
4. `replay_detected` / `token_used`: Adversary replays token from `device-unknown-adversary` with foreign `ip_hash` (rejected).

## How to Run
```bash
python -m simulator --scenario replay
```
