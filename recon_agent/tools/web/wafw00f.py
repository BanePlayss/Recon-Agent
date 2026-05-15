from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)

_WAF_RE = re.compile(r"is behind (.+?)(?:\s*\(|$)", re.IGNORECASE)
_NO_WAF_RE = re.compile(r"No WAF detected|does not seem to be behind", re.IGNORECASE)


class Wafw00fTool(Tool):
    name = "wafw00f"
    category = ToolCategory.RECON_ACTIVE
    requires_approval = False
    timeout_s = 60

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        return bool(target and (target.startswith("http://") or target.startswith("https://")))

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.validate_args(target):
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                stdout="",
                stderr=f"Target must be HTTP/HTTPS URL: {target!r}",
                duration_s=0.0,
            )

        start = time.monotonic()
        cmd = ["wafw00f", target, "-a", "-o", "-"]

        logger.info("wafw00f.start", target=target)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            waf_match = _WAF_RE.search(stdout)
            if waf_match:
                waf_name = waf_match.group(1).strip()
                findings_raw.append({"waf_detected": True, "waf_name": waf_name})
                logger.info("wafw00f.done", target=target, waf=waf_name)
            elif _NO_WAF_RE.search(stdout):
                findings_raw.append({"waf_detected": False, "waf_name": None})
                logger.info("wafw00f.done", target=target, waf=None)

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
