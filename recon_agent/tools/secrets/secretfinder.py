from __future__ import annotations

import asyncio
import json
import re
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)

# SecretFinder may be installed as a script or via pip
_BINARIES = ["SecretFinder", "secretfinder", "secretfinder.py"]


def _find_binary() -> str | None:
    import shutil
    for name in _BINARIES:
        found = shutil.which(name)
        if found:
            return found
    common_paths = [
        "/opt/SecretFinder/SecretFinder.py",
        "/usr/share/SecretFinder/SecretFinder.py",
    ]
    for p in common_paths:
        if Path(p).exists():
            return f"python3 {p}"
    return None


class SecretFinderTool(Tool):
    name = "secretfinder"
    category = ToolCategory.SECRETS
    requires_approval = False
    timeout_s = 120

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        return bool(target and (target.startswith("http://") or target.startswith("https://")))

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.validate_args(target):
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr=f"Target must be HTTP/HTTPS URL: {target!r}", duration_s=0.0,
            )

        binary = _find_binary()
        if not binary:
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr="SecretFinder not found. Install: pip install secretfinder or clone from GitHub",
                duration_s=0.0,
            )

        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_path = Path(tf.name)

        if binary.startswith("python3 "):
            script = binary.split(" ", 1)[1]
            cmd = ["python3", script, "-i", target, "-o", "json", "-e", str(output_path)]
        else:
            cmd = [binary, "-i", target, "-o", "json", "-e", str(output_path)]

        logger.info("secretfinder.start", target=target)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            if output_path.exists():
                raw_text = output_path.read_text(encoding="utf-8", errors="replace").strip()
                if raw_text:
                    try:
                        data = json.loads(raw_text)
                        findings_raw = data if isinstance(data, list) else [data]
                    except json.JSONDecodeError:
                        pass

            logger.info("secretfinder.done", target=target, secrets=len(findings_raw))
            return ToolResult(
                tool=self.name,
                target=target,
                status="success" if rc == 0 else "error",
                stdout=stdout,
                stderr=stderr,
                duration_s=duration,
                findings_raw=findings_raw,
            )
        except asyncio.TimeoutError:
            duration = time.monotonic() - start
            return ToolResult(
                tool=self.name, target=target, status="timeout",
                stdout="", stderr=f"Timed out after {self.timeout_s}s", duration_s=duration,
            )
        finally:
            output_path.unlink(missing_ok=True)
