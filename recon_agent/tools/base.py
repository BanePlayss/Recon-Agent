from __future__ import annotations

import asyncio
import shlex
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel

from recon_agent.core.state import ToolCategory

logger = structlog.get_logger(__name__)


class ToolResult(BaseModel):
    tool: str
    target: str
    status: str  # "success" | "error" | "timeout"
    stdout: str
    stderr: str
    duration_s: float
    findings_raw: list[dict[str, Any]] = []


class ToolExecutionError(Exception):
    pass


class Tool(ABC):
    name: str
    category: ToolCategory
    requires_approval: bool = False
    timeout_s: int = 300

    @abstractmethod
    async def run(self, target: str, **kwargs: Any) -> ToolResult: ...

    @abstractmethod
    def validate_args(self, target: str, **kwargs: Any) -> bool: ...

    async def _run_subprocess(
        self,
        cmd: list[str],
        timeout_s: int | None = None,
        output_file: Path | None = None,
    ) -> tuple[str, str, int]:
        """Execute a subprocess and return (stdout, stderr, returncode)."""
        timeout = timeout_s or self.timeout_s

        # Validate no shell injection — only allow safe chars in args
        for arg in cmd:
            if any(c in arg for c in [";", "&&", "||", "`", "$("]):
                raise ToolExecutionError(f"Potentially unsafe argument detected: {arg!r}")

        log = logger.bind(tool=self.name, cmd=shlex.join(cmd))
        log.debug("tool.subprocess_start")

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            elapsed = time.monotonic() - start
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            log.debug(
                "tool.subprocess_done",
                returncode=proc.returncode,
                elapsed_s=f"{elapsed:.1f}",
            )

            if output_file and output_file.exists():
                stdout = output_file.read_text(encoding="utf-8", errors="replace")

            return stdout, stderr, proc.returncode or 0

        except asyncio.TimeoutError:
            elapsed = time.monotonic() - start
            log.warning("tool.subprocess_timeout", elapsed_s=f"{elapsed:.1f}")
            raise
