from __future__ import annotations

import re
import time
from typing import Any

import httpx
import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)

_FQDN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CRT_URL = "https://crt.sh/"


class CrtshTool(Tool):
    name = "crtsh"
    category = ToolCategory.RECON_PASSIVE
    requires_approval = False
    timeout_s = 60

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        domain = target.lstrip("*.")
        if _IP_RE.match(domain):
            return False
        return bool(_FQDN_RE.match(domain))

    def is_available(self) -> bool:
        # HTTP-based tool — always available if network is reachable
        return True

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.validate_args(target):
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr=f"Invalid domain: {target!r}", duration_s=0.0,
            )

        domain = target.lstrip("*.")
        start = time.monotonic()
        logger.info("crtsh.start", domain=domain)

        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                response = await client.get(
                    _CRT_URL,
                    params={"q": f"%.{domain}", "output": "json"},
                    headers={"Accept": "application/json"},
                )
            duration = time.monotonic() - start

            if response.status_code != 200:
                return ToolResult(
                    tool=self.name, target=target, status="error",
                    stdout="", stderr=f"crt.sh returned {response.status_code}",
                    duration_s=duration,
                )

            entries = response.json()
            seen: set[str] = set()
            subdomains = []
            for entry in entries:
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub and _FQDN_RE.match(sub) and sub not in seen:
                        seen.add(sub)
                        subdomains.append(sub)

            findings_raw = [{"subdomain": s} for s in sorted(seen)]
            stdout = "\n".join(sorted(seen))
            logger.info("crtsh.done", domain=domain, found=len(seen))
            return ToolResult(
                tool=self.name, target=target, status="success",
                stdout=stdout, stderr="",
                duration_s=duration,
                findings_raw=findings_raw,
            )
        except httpx.TimeoutException:
            duration = time.monotonic() - start
            return ToolResult(
                tool=self.name, target=target, status="timeout",
                stdout="", stderr=f"crt.sh request timed out after {self.timeout_s}s",
                duration_s=duration,
            )
        except Exception as e:
            duration = time.monotonic() - start
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr=str(e), duration_s=duration,
            )
