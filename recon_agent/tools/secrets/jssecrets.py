from __future__ import annotations

import asyncio
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import ToolCategory
from recon_agent.tools.base import Tool, ToolResult

logger = structlog.get_logger(__name__)

# Regex patterns for common high-value secrets in JS
_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "github_token": re.compile(r"gh[pousr]_[0-9a-zA-Z]{36,}"),
    "stripe_key": re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "sendgrid_key": re.compile(r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"),
    "jwt_token": re.compile(r"eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}"),
    "private_key_header": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "basic_auth_url": re.compile(r"https?://[^:@\s]+:[^@\s]{8,}@[^/\s]"),
}

_SEVERITY_BY_TYPE = {
    "aws_access_key": "critical",
    "aws_secret_key": "critical",
    "github_token": "high",
    "stripe_key": "critical",
    "slack_token": "high",
    "google_api_key": "high",
    "sendgrid_key": "high",
    "jwt_token": "medium",
    "private_key_header": "critical",
    "basic_auth_url": "high",
}


class JsSecretsTool(Tool):
    """
    JS secrets discovery pipeline:
    1. Uses katana to crawl and extract JS file URLs from the target
    2. Fetches each JS file and scans it for hardcoded secrets/API keys
    3. Falls back to secretfinder/trufflehog when katana is unavailable

    This is the highest-ROI automated finding type: valid AWS/Stripe keys
    typically pay $500–$2000 on HackerOne programs.
    """

    name = "jssecrets"
    category = ToolCategory.SECRETS
    requires_approval = False
    timeout_s = 600
    description = "Crawl target JS files and scan for hardcoded secrets/API keys (katana + pattern matching)"

    def is_available(self) -> bool:
        # The regex-based fallback is always available (uses httpx Python lib).
        # Katana improves coverage but is not required.
        return True

    def validate_args(self, target: str, **kwargs: Any) -> bool:
        return bool(
            target and (target.startswith("http://") or target.startswith("https://"))
        )

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.validate_args(target):
            return ToolResult(
                tool=self.name, target=target, status="error",
                stdout="", stderr=f"Target must be HTTP/HTTPS URL: {target!r}",
                duration_s=0.0,
            )

        start = time.monotonic()
        js_urls: list[str] = []

        # Step 1: collect JS URLs
        if shutil.which("katana"):
            js_urls = await self._katana_js_urls(target)
        else:
            js_urls = await self._httpx_js_urls(target)

        if not js_urls:
            return ToolResult(
                tool=self.name, target=target, status="success",
                stdout="No JS files found.",
                stderr="",
                duration_s=time.monotonic() - start,
                findings_raw=[],
            )

        logger.info("jssecrets.scanning", js_files=len(js_urls))

        # Step 2: scan each JS file for secrets
        findings_raw: list[dict[str, Any]] = []
        output_lines = [f"Scanned {len(js_urls)} JS files from {target}"]

        import httpx
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=15.0, verify=False
        ) as client:
            for js_url in js_urls[:100]:  # cap at 100 JS files per target
                try:
                    resp = await client.get(js_url)
                    if resp.status_code != 200:
                        continue
                    content = resp.text
                    for secret_type, pattern in _SECRET_PATTERNS.items():
                        matches = pattern.findall(content)
                        for match in matches[:5]:  # cap per-file per-type
                            val = match if isinstance(match, str) else match[0]
                            findings_raw.append({
                                "type": secret_type,
                                "url": js_url,
                                "value_snippet": val[:60],
                                "severity": _SEVERITY_BY_TYPE.get(secret_type, "high"),
                            })
                            output_lines.append(
                                f"[{_SEVERITY_BY_TYPE.get(secret_type,'high').upper()}] "
                                f"{secret_type} in {js_url}"
                            )
                except Exception as e:
                    logger.debug("jssecrets.fetch_error", url=js_url, error=str(e))

        duration = time.monotonic() - start
        logger.info("jssecrets.done", target=target, secrets=len(findings_raw))
        return ToolResult(
            tool=self.name, target=target,
            status="success",
            stdout="\n".join(output_lines),
            stderr="",
            duration_s=duration,
            findings_raw=findings_raw,
        )

    async def _katana_js_urls(self, target: str) -> list[str]:
        """Use katana to crawl and return all discovered JS file URLs."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
            output_path = Path(tf.name)

        cmd = [
            "katana",
            "-u", target,
            "-silent",
            "-o", str(output_path),
            "-depth", "3",
            "-js-crawl",
            "-timeout", "10",
            "-extension-match", "js",
        ]
        try:
            stdout, _stderr, _rc = await self._run_subprocess(
                cmd, timeout_s=120, output_file=output_path
            )
            urls = [
                line.strip() for line in stdout.splitlines()
                if line.strip().endswith(".js") and line.strip().startswith("http")
            ]
            return urls
        except asyncio.TimeoutError:
            return []
        finally:
            output_path.unlink(missing_ok=True)

    async def _httpx_js_urls(self, target: str) -> list[str]:
        """Minimal fallback: fetch the target page and extract script src URLs."""
        import httpx
        import re as _re
        try:
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=15.0, verify=False
            ) as client:
                resp = await client.get(target)
                body = resp.text
                src_re = _re.compile(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']')
                found: list[str] = []
                base = target.rstrip("/")
                for match in src_re.finditer(body):
                    url = match.group(1)
                    if url.startswith("http"):
                        found.append(url)
                    elif url.startswith("/"):
                        from urllib.parse import urlparse
                        parsed = urlparse(target)
                        found.append(f"{parsed.scheme}://{parsed.netloc}{url}")
                return found[:50]
        except Exception:
            return []
