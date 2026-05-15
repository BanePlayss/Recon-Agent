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

_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]


def _find_wordlist(custom: str | None = None) -> str | None:
    if custom and Path(custom).exists():
        return custom
    for path in _WORDLIST_CANDIDATES:
        if Path(path).exists():
            return path
    return None


class FfufTool(Tool):
    name = "ffuf"
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
                stderr=f"Target must be an HTTP/HTTPS URL, got: {target!r}",
                duration_s=0.0,
            )

        wordlist = _find_wordlist(kwargs.get("wordlist"))
        if not wordlist:
            return ToolResult(
                tool=self.name,
                target=target,
                status="error",
                stdout="",
                stderr="No wordlist found. Install seclists or dirb wordlists.",
                duration_s=0.0,
            )

        start = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_path = Path(tf.name)

        url = target.rstrip("/") + "/FUZZ"
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-o", str(output_path),
            "-of", "json",
            "-s",
            "-t", "50",
        ]

        logger.info("ffuf.start", target=target, wordlist=wordlist)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            if output_path.exists():
                raw_text = output_path.read_text(encoding="utf-8", errors="replace")
                try:
                    data = json.loads(raw_text)
                    findings_raw = data.get("results", [])
                except json.JSONDecodeError:
                    pass

            logger.info("ffuf.done", target=target, endpoints=len(findings_raw))
            return ToolResult(
                tool=self.name,
                target=target,
                status="success" if rc == 0 else "error",
                stdout=str(findings_raw),
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
