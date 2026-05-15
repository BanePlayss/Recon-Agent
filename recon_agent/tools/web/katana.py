from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)


class KatanaTool(Tool):
    name = "katana"
    category = ToolCategory.WEB_SCAN
    requires_approval = False
    timeout_s = 300

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        return bool(target and (target.startswith("http://") or target.startswith("https://")))

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.validate_args(target):
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                stdout="",
                stderr=f"Target must be HTTP/HTTPS URL, got: {target!r}",
                duration_s=0.0,
            )

        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
            output_path = Path(tf.name)

        depth = str(kwargs.get("depth", 3))
        cmd = [
            "katana",
            "-u", target,
            "-silent",
            "-o", str(output_path),
            "-depth", depth,
            "-js-crawl",
            "-known-files", "all",
            "-timeout", "10",
        ]

        logger.info("katana.start", target=target)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd, output_file=output_path)
            duration = time.monotonic() - start

            endpoints = [
                {"url": line.strip()}
                for line in stdout.splitlines()
                if line.strip() and line.strip().startswith("http")
            ]

            logger.info("katana.done", target=target, endpoints=len(endpoints))
            return ToolResult(
                tool=self.name,
                target=target,
                status="success" if rc == 0 else "error",
                stdout=stdout,
                stderr=stderr,
                duration_s=duration,
                findings_raw=endpoints,
            )
        except asyncio.TimeoutError:
            duration = time.monotonic() - start
            return ToolResult(
                tool=self.name,
                target=target,
                status="timeout",
                stdout="",
                stderr=f"Timed out after {self.timeout_s}s",
                duration_s=duration,
            )
        finally:
            output_path.unlink(missing_ok=True)
