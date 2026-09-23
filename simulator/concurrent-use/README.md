# Concurrent Use Attack Simulation

## Overview
Simulates the concurrent presentation of the same authentication token across two distinct physical devices and IP networks within a virtually simultaneous time frame (5 seconds apart).

## Event Sequence
1. `token_issued`: Token issued to user session on `device-workstation-office` (accepted).
2. `token_used`: User accesses `/api/v1/documents` from office device (accepted).
3. `token_used`: Same token presented 5 seconds later from `device-rogue-clone` in Germany (accepted).
4. `suspicious_device`: Concurrent device anomaly triggered (rejected).

## How to Run
```bash
python -m simulator --scenario concurrent-use
```
