#!/usr/bin/env python3
"""Convenience launcher for local JSON CLI.

Inserts this repository root explicitly so it also works under ``python -I``
(where Python's safe-path mode does not prepend the script directory).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from eraseanchor.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
