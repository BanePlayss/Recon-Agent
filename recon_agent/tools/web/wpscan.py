from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)


class WpscanTool(Tool):
    name = "wpscan"
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

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_path = Path(tf.name)

        cmd = [
            "wpscan",
            "--url", target,
            "-o", str(output_path),
            "--format", "json",
            "--no-update",
            "--random-user-agent",
        ]

        api_token = os.environ.get("WPSCAN_API_TOKEN")
        if api_token:
            cmd += ["--api-token", api_token]

        logger.info("wpscan.start", target=target)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            if output_path.exists():
                raw_text = output_path.read_text(encoding="utf-8", errors="replace").strip()
                if raw_text:
                    try:
                        data = json.loads(raw_text)
                        vulns = data.get("vulnerabilities", [])
                        findings_raw = vulns if isinstance(vulns, list) else []
                    except json.JSONDecodeError:
                        pass

            logger.info("wpscan.done", target=target, findings=len(findings_raw))
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
        finally:
            output_path.unlink(missing_ok=True)
