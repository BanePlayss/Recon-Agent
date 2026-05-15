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


class HttpxTool(Tool):
    name = "httpx"
    category = ToolCategory.RECON_ACTIVE
    requires_approval = False
    timeout_s = 180

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        return bool(target and len(target) < 2048)

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.validate_args(target):
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                stdout="",
                stderr=f"Invalid target: {target!r}",
                duration_s=0.0,
            )

        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
            output_path = Path(tf.name)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as inf:
            targets_path = Path(inf.name)

        # Handle both single target and list of targets
        if isinstance(target, str) and "\n" not in target and "," not in target:
            targets_path.write_text(target + "\n", encoding="utf-8")
        else:
            lines = [t.strip() for t in target.replace(",", "\n").splitlines() if t.strip()]
            targets_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        cmd = [
            "httpx",
            "-l", str(targets_path),
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-json",
            "-o", str(output_path),
        ]

        logger.info("httpx.start", target=target[:100])

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

            logger.info("httpx.done", hosts_found=len(findings_raw))
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
