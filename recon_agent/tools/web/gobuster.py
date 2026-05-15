from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult
from recon_agent.tools.web.ffuf import _find_wordlist

logger = structlog.get_logger(__name__)

_DNS_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

_MODES = {"dir", "dns", "vhost"}


class GobusterTool(Tool):
    name = "gobuster"
    category = ToolCategory.WEB_SCAN
    requires_approval = False
    timeout_s = 300

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        mode = kwargs.get("mode", "dir")
        if mode not in _MODES:
            return False
        if mode == "dir":
            return bool(target and (target.startswith("http://") or target.startswith("https://")))
        if mode == "vhost":
            return bool(target and (target.startswith("http://") or target.startswith("https://")))
        # dns: target should be a domain (no protocol)
        return bool(target and not target.startswith("http"))

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        mode = kwargs.get("mode", "dir")
        wordlist = kwargs.get("wordlist")

        if not self.validate_args(target, mode=mode):
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr=f"Invalid target/mode combo: {target!r} mode={mode}", duration_s=0.0,
            )

        resolved_wordlist = _find_wordlist(wordlist)
        if not resolved_wordlist:
            for candidate in _DNS_WORDLISTS:
                from pathlib import Path
                if Path(candidate).exists():
                    resolved_wordlist = candidate
                    break
        if not resolved_wordlist:
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr="No wordlist found. Install seclists.", duration_s=0.0,
            )

        start = time.monotonic()

        cmd = [
            "gobuster", mode,
            "-u" if mode in ("dir", "vhost") else "-d", target,
            "-w", resolved_wordlist,
            "-q",
            "--no-progress",
        ]

        if mode == "dir":
            cmd += ["-s", "200,204,301,302,307,401,403"]
        elif mode == "dns":
            cmd += ["-r"]  # use system resolver

        logger.info("gobuster.start", target=target, mode=mode)

        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw = [
                {"result": line.strip()}
                for line in stdout.splitlines()
                if line.strip() and not line.startswith("=")
            ]

            logger.info("gobuster.done", target=target, results=len(findings_raw))
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
