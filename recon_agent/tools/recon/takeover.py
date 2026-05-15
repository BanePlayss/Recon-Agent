from __future__ import annotations

import asyncio
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)

# Fingerprints for common services that are vulnerable to subdomain takeover.
# Maps service name → strings that appear in the HTTP body when the subdomain
# is dangling (not configured / repo deleted / etc.).
_TAKEOVER_FINGERPRINTS: dict[str, list[str]] = {
    "github-pages": ["There isn't a GitHub Pages site here"],
    "heroku": ["No such app", "herokucdn.com/error-pages/no-such-app"],
    "shopify": ["Sorry, this shop is currently unavailable"],
    "fastly": ["Fastly error: unknown domain"],
    "pantheon": ["The gods are wise, but do not know of the site which you seek"],
    "zendesk": ["Help Center Closed"],
    "tumblr": ["Whatever you were looking for doesn't currently exist"],
    "wordpress": ["Do you want to register"],
    "aws-s3": ["NoSuchBucket", "The specified bucket does not exist"],
    "azure": ["404 Web Site not found"],
    "ghost": ["The thing you were looking for is no longer here"],
    "readme-io": ["Project doesnt exist yet"],
    "cargo": ["If you're moving your domain away from Cargo"],
    "unbounce": ["The requested URL was not found on this server"],
    "surge": ["project not found"],
}


class SubdomainTakeoverTool(Tool):
    """
    Detects potential subdomain takeovers using two methods:
    1. nuclei with the 'takeovers' tag (preferred — wide template coverage)
    2. Pure-Python CNAME fingerprint check via httpx (fallback, always available)
    """

    name = "takeover"
    category = ToolCategory.RECON_ACTIVE
    requires_approval = False
    timeout_s = 300
    description = "Detect subdomain takeover vulnerabilities (nuclei takeover templates + CNAME fingerprint check)"

    def is_available(self) -> bool:
        # Available if nuclei or httpx (Python) is present; httpx Python lib is
        # always available as a dep, so this tool is always usable.
        return True

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        return bool(target and target.strip())

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.validate_args(target):
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr="Empty target", duration_s=0.0,
            )

        start = time.monotonic()

        # Prefer nuclei takeover scan when available
        if shutil.which("nuclei"):
            return await self._run_nuclei(target, start)

        # Fallback: pure-Python fingerprint check
        return await self._run_fingerprint(target, start)

    async def _run_nuclei(self, target: str, start: float) -> ToolResult:
        targets = [t.strip() for t in target.replace(",", "\n").splitlines() if t.strip()]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tf:
            tf.write("\n".join(targets))
            targets_file = Path(tf.name)

        out_file = targets_file.with_suffix(".json")
        cmd = [
            "nuclei",
            "-l", str(targets_file),
            "-tags", "takeovers",
            "-severity", "critical,high,medium",
            "-json-export", str(out_file),
            "-silent",
            "-timeout", "10",
        ]

        logger.info("takeover.nuclei_start", targets=len(targets))
        try:
            stdout, stderr, rc = await self._run_subprocess(cmd)
            duration = time.monotonic() - start

            findings_raw: list[dict[str, Any]] = []
            if out_file.exists():
                import json
                for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        findings_raw.append(json.loads(line))
                    except Exception:
                        pass

            logger.info("takeover.nuclei_done", findings=len(findings_raw))
            return ToolResult(
                tool=self.name, target=target,
                status="success" if rc == 0 else "error",
                stdout=stdout, stderr=stderr,
                duration_s=duration, findings_raw=findings_raw,
            )
        except asyncio.TimeoutError:
            return ToolResult(
                tool=self.name, target=target, status="timeout",
                stdout="", stderr=f"Timed out after {self.timeout_s}s",
                duration_s=time.monotonic() - start,
            )
        finally:
            targets_file.unlink(missing_ok=True)
            out_file.unlink(missing_ok=True)

    async def _run_fingerprint(self, target: str, start: float) -> ToolResult:
        """Check each target host for takeover fingerprints using httpx."""
        import httpx

        targets = [t.strip() for t in target.replace(",", "\n").splitlines() if t.strip()]
        findings_raw: list[dict[str, Any]] = []
        output_lines: list[str] = []

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            verify=False,
        ) as client:
            for host in targets:
                url = host if host.startswith("http") else f"https://{host}"
                try:
                    resp = await client.get(url)
                    body = resp.text[:4096]
                    for service, fingerprints in _TAKEOVER_FINGERPRINTS.items():
                        for fp in fingerprints:
                            if fp.lower() in body.lower():
                                findings_raw.append({
                                    "host": host,
                                    "service": service,
                                    "fingerprint": fp,
                                    "status_code": resp.status_code,
                                })
                                output_lines.append(
                                    f"[TAKEOVER] {host} → {service} ({fp!r})"
                                )
                                break
                except Exception as e:
                    output_lines.append(f"[SKIP] {host}: {e}")

        duration = time.monotonic() - start
        logger.info("takeover.fingerprint_done", findings=len(findings_raw))
        return ToolResult(
            tool=self.name, target=target, status="success",
            stdout="\n".join(output_lines),
            stderr="",
            duration_s=duration,
            findings_raw=findings_raw,
        )
