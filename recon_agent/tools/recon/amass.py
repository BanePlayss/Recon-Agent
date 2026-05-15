from __future__ import annotations

import asyncio
import re
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)

_FQDN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class AmassTool(Tool):
    name = "amass"
    category = ToolCategory.RECON_PASSIVE
    requires_approval = False
    timeout_s = 600

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        domain = target.lstrip("*.")
        if _IP_RE.match(domain):
            return False
        return bool(_FQDN_RE.match(domain))

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.validate_args(target):
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                stdout="",
                stderr=f"Invalid target domain: {target!r}",
                duration_s=0.0,
            )

        domain = target.lstrip("*.")
        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
            output_path = Path(tf.name)

        cmd = ["amass", "enum", "-passive", "-d", domain, "-o", str(output_path)]
        logger.info("amass.start", domain=domain)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd, output_file=output_path)
            duration = time.monotonic() - start

            subdomains = [
                line.strip()
                for line in stdout.splitlines()
                if line.strip() and _FQDN_RE.match(line.strip()) and not _IP_RE.match(line.strip())
            ]

            logger.info("amass.done", domain=domain, found=len(subdomains))
            return ToolResult(
                tool=self.name,
                target=target,
                status="success" if rc == 0 else "error",
                stdout=stdout,
                stderr=stderr,
                duration_s=duration,
                findings_raw=[{"subdomain": s} for s in subdomains],
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
