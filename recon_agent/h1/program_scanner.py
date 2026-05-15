from __future__ import annotations

"""
HackerOne program scanner — finds and scores programs for automated hunting.

Uses the HackerOne public API (authenticated with H1_USERNAME + H1_API_TOKEN).
Falls back to a curated list of consistently-paying programs when no credentials
are configured.

ROI scoring formula:
  score = (critical_bounty * 0.35)
        + (high_bounty * 0.25)
        + (response_efficiency * 0.25)   # % of reports rewarded
        + (freshness_bonus * 0.15)        # new/updated scope in last 30 days

Programs are sorted descending by score so callers can pick the top N.
"""

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_H1_API_BASE = "https://api.hackerone.com/v1"

# Curated fallback list for when no H1 API credentials are available.
# These programs have publicly documented good response + bounty histories.
_FALLBACK_PROGRAMS = [
    {
        "handle": "security",
        "name": "HackerOne",
        "url": "https://hackerone.com/security",
        "min_bounty_critical": 2500,
        "min_bounty_high": 1000,
        "response_efficiency_percentage": 97,
        "scope_updated_at": None,
    },
    {
        "handle": "github_enterprise",
        "name": "GitHub Enterprise",
        "url": "https://hackerone.com/github_enterprise",
        "min_bounty_critical": 30000,
        "min_bounty_high": 4000,
        "response_efficiency_percentage": 96,
        "scope_updated_at": None,
    },
    {
        "handle": "shopify",
        "name": "Shopify",
        "url": "https://hackerone.com/shopify",
        "min_bounty_critical": 5000,
        "min_bounty_high": 2000,
        "response_efficiency_percentage": 96,
        "scope_updated_at": None,
    },
    {
        "handle": "verizon_media",
        "name": "Yahoo / Verizon Media",
        "url": "https://hackerone.com/verizon_media",
        "min_bounty_critical": 15000,
        "min_bounty_high": 3000,
        "response_efficiency_percentage": 94,
        "scope_updated_at": None,
    },
    {
        "handle": "gitlab",
        "name": "GitLab",
        "url": "https://hackerone.com/gitlab",
        "min_bounty_critical": 20000,
        "min_bounty_high": 3000,
        "response_efficiency_percentage": 95,
        "scope_updated_at": None,
    },
    {
        "handle": "x",
        "name": "X (Twitter)",
        "url": "https://hackerone.com/x",
        "min_bounty_critical": 10080,
        "min_bounty_high": 2520,
        "response_efficiency_percentage": 90,
        "scope_updated_at": None,
    },
    {
        "handle": "cloudflare",
        "name": "Cloudflare",
        "url": "https://hackerone.com/cloudflare",
        "min_bounty_critical": 3000,
        "min_bounty_high": 1000,
        "response_efficiency_percentage": 95,
        "scope_updated_at": None,
    },
    {
        "handle": "uber",
        "name": "Uber",
        "url": "https://hackerone.com/uber",
        "min_bounty_critical": 10000,
        "min_bounty_high": 5000,
        "response_efficiency_percentage": 93,
        "scope_updated_at": None,
    },
    {
        "handle": "dropbox",
        "name": "Dropbox",
        "url": "https://hackerone.com/dropbox",
        "min_bounty_critical": 32768,
        "min_bounty_high": 6144,
        "response_efficiency_percentage": 97,
        "scope_updated_at": None,
    },
    {
        "handle": "airbnb",
        "name": "Airbnb",
        "url": "https://hackerone.com/airbnb",
        "min_bounty_critical": 15000,
        "min_bounty_high": 5000,
        "response_efficiency_percentage": 92,
        "scope_updated_at": None,
    },
]


@dataclass
class ProgramTarget:
    handle: str
    name: str
    program_url: str
    min_bounty_critical: int
    min_bounty_high: int
    response_efficiency_pct: float
    roi_score: float
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    recently_updated: bool = False

    @property
    def weekly_expected_usd(self) -> float:
        """Rough model: 1 critical/2weeks + 2 high/week at given bounties."""
        return (self.min_bounty_critical / 14) + (self.min_bounty_high * 2 / 7)


def _roi_score(
    critical_bounty: float,
    high_bounty: float,
    response_efficiency: float,
    freshness_bonus: float = 0.0,
) -> float:
    """Normalized ROI score (higher = better for automated hunting)."""
    # Normalize bounty values on log scale to prevent mega-programs dominating
    import math
    c = math.log1p(critical_bounty) / math.log1p(30000)
    h = math.log1p(high_bounty) / math.log1p(5000)
    r = response_efficiency / 100.0
    return round(c * 0.35 + h * 0.25 + r * 0.25 + freshness_bonus * 0.15, 4)


def _freshness_bonus(updated_at: str | None) -> float:
    """Return 0.0–1.0 bonus based on how recently scope was updated."""
    if not updated_at:
        return 0.0
    try:
        dt = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - dt).days
        if age_days <= 7:
            return 1.0
        if age_days <= 30:
            return 0.5
    except Exception:
        pass
    return 0.0


async def fetch_programs(
    page_size: int = 50,
    max_pages: int = 4,
) -> list[ProgramTarget]:
    """
    Fetch bounty programs from the H1 API when H1_USERNAME and H1_API_TOKEN
    are set. Returns scored ProgramTarget list sorted by ROI score desc.

    Falls back to _FALLBACK_PROGRAMS if credentials are missing.
    """
    username = os.environ.get("H1_USERNAME", "")
    api_token = os.environ.get("H1_API_TOKEN", "")

    if not username or not api_token:
        logger.info("h1.scanner.fallback", reason="no_credentials")
        return _score_fallback()

    return await _fetch_from_api(username, api_token, page_size, max_pages)


def _score_fallback() -> list[ProgramTarget]:
    targets: list[ProgramTarget] = []
    for prog in _FALLBACK_PROGRAMS:
        score = _roi_score(
            prog["min_bounty_critical"],
            prog["min_bounty_high"],
            prog["response_efficiency_percentage"],
            _freshness_bonus(prog.get("scope_updated_at")),
        )
        targets.append(ProgramTarget(
            handle=prog["handle"],
            name=prog["name"],
            program_url=prog["url"],
            min_bounty_critical=prog["min_bounty_critical"],
            min_bounty_high=prog["min_bounty_high"],
            response_efficiency_pct=prog["response_efficiency_percentage"],
            roi_score=score,
        ))
    targets.sort(key=lambda p: p.roi_score, reverse=True)
    return targets


async def _fetch_from_api(
    username: str,
    api_token: str,
    page_size: int,
    max_pages: int,
) -> list[ProgramTarget]:
    import httpx

    auth = (username, api_token)
    targets: list[ProgramTarget] = []

    async with httpx.AsyncClient(timeout=20.0) as client:
        page = 1
        while page <= max_pages:
            url = (
                f"{_H1_API_BASE}/hackers/programs"
                f"?page[size]={page_size}&page[number]={page}"
                f"&filter[bounties_enabled]=true"
                f"&filter[submission_state]=open"
            )
            try:
                resp = await client.get(url, auth=auth)
                resp.raise_for_status()
            except Exception as e:
                logger.warning("h1.api_error", page=page, error=str(e))
                break

            data = resp.json()
            programs: list[dict[str, Any]] = data.get("data", [])
            if not programs:
                break

            for prog in programs:
                attrs = prog.get("attributes", {})
                if not attrs.get("offers_bounties"):
                    continue
                if attrs.get("submission_state") != "open":
                    continue

                bountytable = attrs.get("structured_scope", {})
                critical_b = float(attrs.get("minimum_bounty_table", {}).get("critical", 0) or 0)
                high_b = float(attrs.get("minimum_bounty_table", {}).get("high", 0) or 0)
                resp_eff = float(attrs.get("response_efficiency_percentage") or 0)
                updated = attrs.get("updated_at")

                score = _roi_score(critical_b, high_b, resp_eff, _freshness_bonus(updated))
                handle = attrs.get("handle", prog.get("id", "unknown"))
                targets.append(ProgramTarget(
                    handle=handle,
                    name=attrs.get("name", handle),
                    program_url=f"https://hackerone.com/{handle}",
                    min_bounty_critical=int(critical_b),
                    min_bounty_high=int(high_b),
                    response_efficiency_pct=resp_eff,
                    roi_score=score,
                    recently_updated=_freshness_bonus(updated) > 0,
                ))

            meta = data.get("meta", {})
            if not meta.get("next_page"):
                break
            page += 1

    targets.sort(key=lambda p: p.roi_score, reverse=True)
    logger.info("h1.scanner.done", programs=len(targets))
    return targets


async def top_programs(n: int = 10) -> list[ProgramTarget]:
    """Return the top-N programs by ROI score."""
    programs = await fetch_programs()
    return programs[:n]
