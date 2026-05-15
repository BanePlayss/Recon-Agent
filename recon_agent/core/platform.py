from __future__ import annotations

"""Cross-platform utilities — path helpers and OS detection."""

import sys
import tempfile
from pathlib import Path

WINDOWS: bool = sys.platform == "win32"

# Prefer sys.executable so the correct Python is used on every platform.
PYTHON_EXE: str = sys.executable


def temp_dir(*parts: str) -> Path:
    """Return a platform-appropriate temp directory, creating it if needed."""
    base = Path(tempfile.gettempdir()) / "recon-agent"
    for part in parts:
        base = base / part
    base.mkdir(parents=True, exist_ok=True)
    return base


def config_dir() -> Path:
    """Return ~/.recon-agent, creating it if needed."""
    d = Path.home() / ".recon-agent"
    d.mkdir(parents=True, exist_ok=True)
    return d
