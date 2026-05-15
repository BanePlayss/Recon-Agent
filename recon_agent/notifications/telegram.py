from __future__ import annotations

"""
Telegram notifier — sends finding alerts via a Telegram bot.

Setup:
  1. Create a bot via @BotFather → get TELEGRAM_BOT_TOKEN
  2. Send any message to your bot, then:
     curl https://api.telegram.org/bot<TOKEN>/getUpdates
     → copy chat_id from the response
  3. Set in ~/.recon-agent/.env:
       TELEGRAM_BOT_TOKEN=123456:ABCdef...
       TELEGRAM_CHAT_ID=987654321

Uses httpx (already a project dependency) — no extra packages needed.
"""

import os
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_BASE = "https://api.telegram.org/bot{token}/{method}"

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


async def send_finding_alert(
    title: str,
    severity: str,
    asset: str,
    program_handle: str,
    source_tool: str,
    confidence: float,
    *,
    bot_token: str = "",
    chat_id: str = "",
) -> bool:
    """Send a Telegram message for a new finding. Returns True on success."""
    token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
    cid = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not cid:
        logger.debug("telegram.no_credentials")
        return False

    emoji = _SEVERITY_EMOJI.get(severity.lower(), "⚪")
    text = (
        f"{emoji} *[{severity.upper()}] New Finding*\n"
        f"*Program:* `{program_handle}`\n"
        f"*Title:* {_escape(title)}\n"
        f"*Asset:* `{_escape(asset[:120])}`\n"
        f"*Tool:* `{source_tool}` | Confidence: {confidence * 100:.0f}%"
    )
    return await _send(token, cid, text)


async def send_summary(
    program_handle: str,
    new_findings: int,
    total_cost_usd: float,
    elapsed_min: float,
    *,
    bot_token: str = "",
    chat_id: str = "",
) -> bool:
    """Send a scan-complete summary message."""
    token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
    cid = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not cid:
        return False

    status = "✅" if new_findings > 0 else "⬜"
    text = (
        f"{status} *Scan complete:* `{program_handle}`\n"
        f"New findings: *{new_findings}*\n"
        f"Cost: ${total_cost_usd:.4f} | Time: {elapsed_min:.1f}min"
    )
    return await _send(token, cid, text)


async def send_new_program_alert(
    handle: str,
    program_url: str,
    roi_score: float,
    *,
    bot_token: str = "",
    chat_id: str = "",
) -> bool:
    """Alert when a new H1 program is discovered."""
    token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
    cid = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not cid:
        return False

    text = (
        f"🆕 *New H1 program detected*\n"
        f"Handle: `{handle}`\n"
        f"URL: {program_url}\n"
        f"ROI Score: `{roi_score:.3f}`\n"
        f"_Queued for next hunt cycle_"
    )
    return await _send(token, cid, text)


async def _send(token: str, chat_id: str, text: str) -> bool:
    import httpx
    url = _BASE.format(token=token, method="sendMessage")
    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            ok = resp.status_code == 200 and resp.json().get("ok")
            if not ok:
                logger.warning("telegram.send_failed", status=resp.status_code, body=resp.text[:200])
            return bool(ok)
    except Exception as e:
        logger.warning("telegram.send_error", error=str(e))
        return False


def _escape(text: str) -> str:
    """Escape Telegram Markdown special characters."""
    for ch in ("_", "*", "`", "["):
        text = text.replace(ch, f"\\{ch}")
    return text
