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
    r"^(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?)$"
)


class MasscanTool(Tool):
    name = "masscan"
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

        ports = kwargs.get("ports", "80,443,8080,8443,8000,8888,3000,5000,9000")
        rate = str(kwargs.get("rate", "1000"))
        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_path = Path(tf.name)

        cmd = [
            "masscan", host,
            "-p", ports,
            "--rate", rate,
            "-oJ", str(output_path),
            "--wait", "2",
        ]

        logger.info("masscan.start", host=host, ports=ports)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            if output_path.exists():
                raw_text = output_path.read_text(encoding="utf-8", errors="replace").strip()
                # masscan JSON has trailing comma — fix it
                raw_text = raw_text.rstrip(",\n") + "]" if raw_text.startswith("[") else raw_text
                if raw_text and raw_text not in ("[]", ""):
                    try:
                        data = json.loads(raw_text)
                        findings_raw = data if isinstance(data, list) else []
                    except json.JSONDecodeError:
                        pass

            logger.info("masscan.done", host=host, open_ports=len(findings_raw))
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
