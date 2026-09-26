#!/usr/bin/env python3
"""
TokenLine Synthetic Token Lifecycle Dataset Generator Script

Generates six reproducible, schema-compliant synthetic authentication & token lifecycle datasets:
- normal.json
- refresh-reuse.json
- expired-token.json
- revoked-token.json
- concurrent-use.json
- impossible-travel.json

Usage:
    python scripts/generate_datasets.py [--seed 42] [--output-dir data/synthetic]
"""

import os
import sys

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from simulator.dataset_generator import main

if __name__ == "__main__":
    main()
