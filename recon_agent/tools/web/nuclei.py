from __future__ import annotations

import asyncio
import json
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)

_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class NucleiTool(Tool):
    name = "nuclei"
    category = ToolCategory.WEB_SCAN
    requires_approval = False
    timeout_s = 600

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        severity = kwargs.get("severity", "critical,high,medium")
        if isinstance(severity, list):
            severity = ",".join(severity)
        parts = {s.strip().lower() for s in severity.split(",")}
        return bool(target) and parts.issubset(_ALLOWED_SEVERITIES)

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        severity = kwargs.get("severity", "critical,high,medium")
        if isinstance(severity, list):
            severity = ",".join(severity)

        if not self.validate_args(target, severity=severity):
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                stdout="",
                stderr=f"Invalid args: target={target!r}, severity={severity!r}",
                duration_s=0.0,
            )

        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
            output_path = Path(tf.name)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as inf:
            targets_path = Path(inf.name)

        if isinstance(target, str) and "\n" not in target and "," not in target:
            targets_path.write_text(target + "\n", encoding="utf-8")
        else:
            lines = [t.strip() for t in target.replace(",", "\n").splitlines() if t.strip()]
            targets_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        cmd = [
            "nuclei",
            "-l", str(targets_path),
            "-silent",
            "-json",
            "-o", str(output_path),
            "-severity", severity,
            "-no-interactsh",
        ]

        logger.info("nuclei.start", target=target[:100], severity=severity)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd, output_file=output_path)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    findings_raw.append(entry)
                except json.JSONDecodeError:
                    pass

            logger.info("nuclei.done", findings=len(findings_raw))
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
            targets_path.unlink(missing_ok=True)
