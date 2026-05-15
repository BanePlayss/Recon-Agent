"""Tests for hunt scheduler, Telegram notifier, H1 monitor, and DB scheduler methods."""
from __future__ import annotations

import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path


# ── Telegram notifier ─────────────────────────────────────────────────────────

class TestTelegramNotifier:
    @pytest.mark.asyncio
    async def test_send_finding_alert_no_creds_returns_false(self, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
        from recon_agent.notifications.telegram import send_finding_alert
        result = await send_finding_alert(
            "XSS", "high", "https://example.com", "acme", "dalfox", 0.9
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_send_finding_alert_with_creds_posts(self, monkeypatch):
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "fake:TOKEN")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "12345")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ok": True}

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=MagicMock(
                post=AsyncMock(return_value=mock_resp)
            ))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_cm

            from recon_agent.notifications.telegram import send_finding_alert
            result = await send_finding_alert(
                "AWS Key Exposed", "critical",
                "https://cdn.example.com/app.js",
                "acme", "jssecrets", 0.95
            )
        assert result is True

    @pytest.mark.asyncio
    async def test_send_summary_no_creds_returns_false(self, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
        from recon_agent.notifications.telegram import send_summary
        result = await send_summary("acme", 3, 0.05, 42.0)
        assert result is False

    @pytest.mark.asyncio
    async def test_send_new_program_alert_no_creds_returns_false(self, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
        from recon_agent.notifications.telegram import send_new_program_alert
        result = await send_new_program_alert("newprog", "https://h1.com/newprog", 0.75)
        assert result is False

    def test_escape_special_chars(self):
        from recon_agent.notifications.telegram import _escape
        escaped = _escape("AWS_KEY [value]")
        assert "_" not in escaped or "\\_" in escaped


# ── H1 monitor ────────────────────────────────────────────────────────────────

class TestH1Monitor:
    def test_scope_hash_stable(self):
        from recon_agent.h1.monitor import _scope_hash
        h1 = _scope_hash(["b.com", "a.com"])
        h2 = _scope_hash(["a.com", "b.com"])
        assert h1 == h2  # order-independent

    def test_scope_hash_changes_on_scope_change(self):
        from recon_agent.h1.monitor import _scope_hash
        h1 = _scope_hash(["a.com"])
        h2 = _scope_hash(["a.com", "b.com"])
        assert h1 != h2

    def test_finding_hash_stable(self):
        from recon_agent.h1.monitor import finding_hash
        h = finding_hash("XSS in search", "https://example.com/search", "acme")
        assert len(h) == 20
        assert h == finding_hash("XSS in search", "https://example.com/search", "acme")

    def test_finding_hash_different_programs(self):
        from recon_agent.h1.monitor import finding_hash
        h1 = finding_hash("XSS", "https://example.com", "acme")
        h2 = finding_hash("XSS", "https://example.com", "beta")
        assert h1 != h2


# ── DB scheduler methods ──────────────────────────────────────────────────────

class TestDbSchedulerMethods:
    def _make_db(self, tmp_path: Path):
        from recon_agent.storage.db import Database
        db = Database(tmp_path / "test.db")
        db.connect()
        return db

    def test_upsert_new_program_returns_true(self, tmp_path):
        db = self._make_db(tmp_path)
        is_new = db.upsert_scheduler_program("acme", "https://h1.com/acme", "abc123")
        assert is_new is True
        db.close()

    def test_upsert_existing_program_returns_false(self, tmp_path):
        db = self._make_db(tmp_path)
        db.upsert_scheduler_program("acme", "https://h1.com/acme", "abc123")
        is_new = db.upsert_scheduler_program("acme", "https://h1.com/acme", "abc123")
        assert is_new is False
        db.close()

    def test_mark_program_scanned(self, tmp_path):
        db = self._make_db(tmp_path)
        db.upsert_scheduler_program("acme", "https://h1.com/acme", "abc123")
        db.mark_program_scanned("acme")
        due = db.get_programs_due(999)  # very long interval → nothing due
        handles = [r["handle"] for r in due]
        assert "acme" not in handles
        db.close()

    def test_get_programs_due_never_scanned(self, tmp_path):
        db = self._make_db(tmp_path)
        db.upsert_scheduler_program("fresh", "https://h1.com/fresh", "xyz")
        due = db.get_programs_due(24)
        handles = [r["handle"] for r in due]
        assert "fresh" in handles
        db.close()

    def test_finding_not_notified_initially(self, tmp_path):
        db = self._make_db(tmp_path)
        assert db.is_finding_notified("nonexistent_hash") is False
        db.close()

    def test_mark_finding_notified(self, tmp_path):
        db = self._make_db(tmp_path)
        db.mark_finding_notified("hash123", "XSS", "high", "acme")
        assert db.is_finding_notified("hash123") is True
        db.close()

    def test_mark_finding_notified_idempotent(self, tmp_path):
        db = self._make_db(tmp_path)
        db.mark_finding_notified("hash456", "SSRF", "critical", "beta")
        db.mark_finding_notified("hash456", "SSRF", "critical", "beta")  # no error
        assert db.is_finding_notified("hash456") is True
        db.close()


# ── Scheduler config ──────────────────────────────────────────────────────────

class TestHuntSchedulerConfig:
    def test_default_notify_severities(self):
        from recon_agent.scheduler.scheduler import HuntScheduler
        s = HuntScheduler()
        assert "critical" in s.notify_severities
        assert "high" in s.notify_severities

    def test_custom_severities(self):
        from recon_agent.scheduler.scheduler import HuntScheduler
        s = HuntScheduler(notify_severities={"critical"})
        assert "high" not in s.notify_severities

    def test_default_interval(self):
        from recon_agent.scheduler.scheduler import HuntScheduler
        s = HuntScheduler()
        assert s.interval_hours == 6.0

    def test_read_pid_returns_none_when_no_file(self):
        from recon_agent.scheduler.scheduler import read_pid, _PID_FILE
        _PID_FILE.unlink(missing_ok=True)
        assert read_pid() is None
