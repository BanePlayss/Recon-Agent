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

_HOST_RE = re.compile(
    r"^(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3})$"
)


class NaabuTool(Tool):
    name = "naabu"
    category = ToolCategory.INFRA_SCAN
    requires_approval = False
    timeout_s = 300

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        return bool(_HOST_RE.match(host))

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        if not self.validate_args(host):
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr=f"Invalid target: {target!r}", duration_s=0.0,
            )

        start = time.monotonic()
        ports = kwargs.get("ports", "top-100")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_path = Path(tf.name)

        cmd = [
            "naabu",
            "-host", host,
            "-p", ports,
            "-silent",
            "-json",
            "-o", str(output_path),
            "-timeout", "5",
        ]

        logger.info("naabu.start", host=host, ports=ports)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd, output_file=output_path)
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

            logger.info("naabu.done", host=host, open_ports=len(findings_raw))
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
