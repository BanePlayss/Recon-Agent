from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)

# testssl.sh may be named differently depending on install
_BINARIES = ["testssl", "testssl.sh"]


def _find_binary() -> str | None:
    for name in _BINARIES:
        if shutil.which(name):
            return name
    return None


class TestsslTool(Tool):
    name = "testssl"
    category = ToolCategory.WEB_SCAN
    requires_approval = False
    timeout_s = 300

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        return bool(host)

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        binary = _find_binary()
        if not binary:
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                stdout="",
                stderr="testssl / testssl.sh not found in PATH",
                duration_s=0.0,
            )

        # Strip protocol — testssl takes host:port
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        if not host:
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr=f"Invalid target: {target!r}", duration_s=0.0,
            )

        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_path = Path(tf.name)

        cmd = [
            binary,
            "--jsonfile", str(output_path),
            "--fast",
            "--color", "0",
            "--quiet",
            host,
        ]

        logger.info("testssl.start", host=host)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            if output_path.exists():
                raw_text = output_path.read_text(encoding="utf-8", errors="replace").strip()
                if raw_text:
                    try:
                        data = json.loads(raw_text)
                        if isinstance(data, list):
                            findings_raw = [
                                entry for entry in data
                                if entry.get("severity") in ("HIGH", "CRITICAL", "MEDIUM")
                            ]
                    except json.JSONDecodeError:
                        pass

            logger.info("testssl.done", host=host, findings=len(findings_raw))
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
