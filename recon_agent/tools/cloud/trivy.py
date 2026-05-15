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

# trivy scans container images, repos, filesystems, and IaC
_SCAN_TYPES = {"image", "repo", "fs", "config"}


class TrivyTool(Tool):
    name = "trivy"
    category = ToolCategory.CLOUD_SCAN
    requires_approval = False
    timeout_s = 300

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        return bool(target)

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        scan_type = kwargs.get("scan_type", "repo")
        if scan_type not in _SCAN_TYPES:
            scan_type = "repo"

        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_path = Path(tf.name)

        cmd = [
            "trivy", scan_type,
            "--format", "json",
            "--output", str(output_path),
            "--severity", "CRITICAL,HIGH,MEDIUM",
            "--quiet",
            target,
        ]

        logger.info("trivy.start", target=target, scan_type=scan_type)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            if output_path.exists():
                raw_text = output_path.read_text(encoding="utf-8", errors="replace").strip()
                if raw_text:
                    try:
                        data = json.loads(raw_text)
                        for result in data.get("Results", []):
                            for vuln in result.get("Vulnerabilities", []):
                                findings_raw.append(vuln)
                            for misconfig in result.get("Misconfigurations", []):
                                findings_raw.append(misconfig)
                    except json.JSONDecodeError:
                        pass

            logger.info("trivy.done", target=target, findings=len(findings_raw))
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
