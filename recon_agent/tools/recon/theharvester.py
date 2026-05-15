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
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class TheHarvesterTool(Tool):
    name = "theHarvester"
    category = ToolCategory.RECON_PASSIVE
    requires_approval = False
    timeout_s = 120

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        domain = target.lstrip("*.")
        if _IP_RE.match(domain):
            return False
        return bool(_FQDN_RE.match(domain))

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        domain = target.lstrip("*.").replace("https://", "").replace("http://", "").split("/")[0]

        if not self.validate_args(domain):
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr=f"Invalid domain: {target!r}", duration_s=0.0,
            )

        sources = kwargs.get("sources", "bing,crtsh,dnsdumpster,hackertarget,rapiddns")
        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
            output_path = Path(tf.name)

        cmd = [
            "theHarvester",
            "-d", domain,
            "-b", sources,
            "-f", str(output_path),
            "-l", "200",
        ]

        logger.info("theHarvester.start", domain=domain, sources=sources)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            emails = list({m.group() for m in _EMAIL_RE.finditer(stdout)})
            subdomains = [
                line.strip()
                for line in stdout.splitlines()
                if line.strip() and _FQDN_RE.match(line.strip())
            ]

            findings_raw = [{"emails": emails, "subdomains": subdomains}]
            logger.info(
                "theHarvester.done",
                domain=domain,
                emails=len(emails),
                subdomains=len(subdomains),
            )
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
