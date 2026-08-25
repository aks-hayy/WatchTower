"""Repository-wide pytest isolation from operator runtime state."""

from __future__ import annotations

import os
from pathlib import Path


TEST_RUNTIME = Path(__file__).resolve().parents[1] / ".test-runtime"
os.environ.setdefault("WATCHTOWER_HOME", str(TEST_RUNTIME))
