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

_FQDN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)


class DnsxTool(Tool):
    name = "dnsx"
    category = ToolCategory.RECON_ACTIVE
    requires_approval = False
    timeout_s = 120

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        return bool(target)

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        start = time.monotonic()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as inf:
            targets_path = Path(inf.name)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as outf:
            output_path = Path(outf.name)

        # target can be a single domain or newline/comma-separated list
        lines = [t.strip() for t in target.replace(",", "\n").splitlines() if t.strip()]
        targets_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        cmd = [
            "dnsx",
            "-l", str(targets_path),
            "-silent",
            "-json",
            "-o", str(output_path),
            "-a", "-aaaa", "-cname", "-mx", "-ns",
        ]

        logger.info("dnsx.start", target=target[:80])

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

            resolved = [e.get("host", "") for e in findings_raw if e.get("a") or e.get("aaaa")]
            logger.info("dnsx.done", resolved=len(resolved))
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
            targets_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)
