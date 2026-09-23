# Impossible Travel Attack Simulation

## Overview
Simulates impossible geographic velocity where an authenticated token is used in Mumbai, India (`IN`), and 4 minutes later the identical token is used in New York, USA (`US`). The implied transit speed between these distant coordinates exceeds physically achievable limits.

## Event Sequence
1. `token_issued`: User login in India (`country: IN`, accepted).
2. `token_used`: User queries `/api/v1/profile` from India (accepted).
3. `suspicious_location`: Token used 4 minutes later from United States (`country: US`, rejected).

## How to Run
```bash
python -m simulator --scenario impossible-travel
```
