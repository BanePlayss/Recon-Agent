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

_HOST_RE = re.compile(
    r"^(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3})$"
)
_OPEN_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(.+)$", re.MULTILINE)


def _extract_ports(nmap_output: str) -> list[dict[str, Any]]:
    ports = []
    for m in _OPEN_PORT_RE.finditer(nmap_output):
        port_num = int(m.group(1))
        service = m.group(2).strip()
        ports.append({"port": port_num, "service": service})
    return ports


class NmapTool(Tool):
    name = "nmap"
    category = ToolCategory.INFRA_SCAN
    requires_approval = False
    timeout_s = 600

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        return bool(_HOST_RE.match(host))

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        if not self.validate_args(host):
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                stdout="",
                stderr=f"Invalid target: {target!r}",
                duration_s=0.0,
            )

        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
            output_path = Path(tf.name)

        fast = kwargs.get("fast", False)
        if fast:
            cmd = ["nmap", "-F", "-T4", "--open", "-oN", str(output_path), host]
        else:
            cmd = ["nmap", "-sV", "-sC", "-T4", "--open", "-oN", str(output_path), host]

        logger.info("nmap.start", host=host, fast=fast)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd, output_file=output_path)
            duration = time.monotonic() - start

            ports = _extract_ports(stdout)
            logger.info("nmap.done", host=host, open_ports=len(ports))

            return ToolResult(
                tool=self.name,
                target=target,
                status="success" if rc == 0 else "error",
                stdout=stdout,
                stderr=stderr,
                duration_s=duration,
                findings_raw=ports,
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
