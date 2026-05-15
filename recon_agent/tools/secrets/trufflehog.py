from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)

_GIT_URL_RE = re.compile(r"^https?://[^\s]+\.git$|^https?://github\.com/[^\s]+")
_LOCAL_PATH_RE = re.compile(r"^(/|\.\.?/)[^\s]*$")


class TrufflehogTool(Tool):
    name = "trufflehog"
    category = ToolCategory.SECRETS
    requires_approval = False
    timeout_s = 300

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        return bool(_GIT_URL_RE.match(target) or _LOCAL_PATH_RE.match(target))

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.validate_args(target):
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                stdout="",
                stderr=f"Target must be a git URL or local path: {target!r}",
                duration_s=0.0,
            )

        start = time.monotonic()

        if target.startswith("http"):
            cmd = ["trufflehog", "git", target, "--json", "--no-update"]
        else:
            cmd = ["trufflehog", "filesystem", target, "--json", "--no-update"]

        logger.info("trufflehog.start", target=target)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings_raw.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

            logger.info("trufflehog.done", target=target, secrets=len(findings_raw))
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
                tool=self.name,
                target=target,
                status="timeout",
                stdout="",
                stderr=f"Timed out after {self.timeout_s}s",
                duration_s=duration,
            )
