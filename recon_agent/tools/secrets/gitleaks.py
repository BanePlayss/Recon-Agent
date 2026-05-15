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

_PATH_RE = re.compile(r"^(/|\.\.?/)[^\s]*$")


class GitleaksTool(Tool):
    name = "gitleaks"
    category = ToolCategory.SECRETS
    requires_approval = False
    timeout_s = 300

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        return bool(_PATH_RE.match(target) and Path(target).exists())

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not Path(target).exists():
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                stdout="",
                stderr=f"Path does not exist: {target!r}",
                duration_s=0.0,
            )

        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_path = Path(tf.name)

        cmd = [
            "gitleaks",
            "detect",
            "--source", target,
            "--report-format", "json",
            "--report-path", str(output_path),
            "--no-git",
        ]

        logger.info("gitleaks.start", target=target)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            if output_path.exists():
                raw_text = output_path.read_text(encoding="utf-8", errors="replace").strip()
                if raw_text:
                    try:
                        data = json.loads(raw_text)
                        findings_raw = data if isinstance(data, list) else []
                    except json.JSONDecodeError:
                        pass

            logger.info("gitleaks.done", target=target, leaks=len(findings_raw))
            # rc=1 means leaks found, not a real error
            return ToolResult(
                tool=self.name,
                target=target,
                status="success",
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
