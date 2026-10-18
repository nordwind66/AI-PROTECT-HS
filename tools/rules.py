#!/usr/bin/env python3
"""AI Prompt Guard -- rule management tool (build-time only; the runtime has no Python dependency).

    python tools/rules.py --help
    python tools/rules.py sources sync --locked
    python tools/rules.py db init
    python tools/rules.py import --source all
    python tools/rules.py diff
    python tools/rules.py validate
    python tools/rules.py publish --version 1.0.0

Only the Python standard library is used.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from apg_rules.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
