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

_PROVIDERS = {"aws", "azure", "gcp", "kubernetes"}


class ProwlerTool(Tool):
    name = "prowler"
    category = ToolCategory.CLOUD_SCAN
    requires_approval = False
    timeout_s = 600

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        provider = kwargs.get("provider", "aws")
        return provider in _PROVIDERS

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        provider = kwargs.get("provider", "aws")

        if not self.validate_args(target, provider=provider):
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr=f"Invalid provider: {provider!r}. Must be one of {_PROVIDERS}",
                duration_s=0.0,
            )

        import shutil
        if not shutil.which("prowler"):
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr="prowler not found. Install: pip install prowler",
                duration_s=0.0,
            )

        # Check for cloud credentials
        if provider == "aws" and not (
            os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE")
        ):
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr="AWS credentials not configured. Set AWS_ACCESS_KEY_ID or AWS_PROFILE.",
                duration_s=0.0,
            )

        start = time.monotonic()

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "prowler", provider,
                "-M", "json",
                "-o", tmpdir,
                "--no-banner",
                "-S",
                "--severity", "critical", "high",
            ]

            logger.info("prowler.start", provider=provider)

            try:
                stdout, stderr, rc = await self._run_subprocess(cmd)
                duration = time.monotonic() - start

                findings_raw: list[dict[str, Any]] = []
                for json_file in Path(tmpdir).glob("*.json"):
                    try:
                        data = json.loads(json_file.read_text(encoding="utf-8"))
                        if isinstance(data, list):
                            findings_raw.extend(
                                e for e in data
                                if e.get("status") in ("FAIL", "CRITICAL")
                            )
                    except (json.JSONDecodeError, OSError):
                        pass

                logger.info("prowler.done", provider=provider, findings=len(findings_raw))
                return ToolResult(
                    tool=self.name, target=target,
                    status="success" if rc == 0 else "error",
                    stdout=stdout, stderr=stderr,
                    duration_s=duration,
                    findings_raw=findings_raw,
                )
            except asyncio.TimeoutError:
                duration = time.monotonic() - start
                return ToolResult(
                    tool=self.name, target=target, status="timeout",
                    stdout="", stderr=f"Timed out after {self.timeout_s}s", duration_s=duration,
                )
