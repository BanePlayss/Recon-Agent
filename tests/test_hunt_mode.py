"""Tests for hunt mode: takeover tool, jssecrets, H1 scanner, batch runner."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from recon_agent.tools.recon.takeover import SubdomainTakeoverTool, _TAKEOVER_FINGERPRINTS
from recon_agent.tools.secrets.jssecrets import JsSecretsTool, _SECRET_PATTERNS
from recon_agent.core.state import ToolCategory


# ── SubdomainTakeoverTool ─────────────────────────────────────────────────────

class TestSubdomainTakeoverTool:
    def test_validate_single_domain(self):
        assert SubdomainTakeoverTool().validate_args("example.com") is True

    def test_validate_comma_list(self):
        assert SubdomainTakeoverTool().validate_args("a.com,b.com,c.com") is True

    def test_validate_url(self):
        assert SubdomainTakeoverTool().validate_args("https://example.com") is True

    def test_rejects_empty(self):
        assert SubdomainTakeoverTool().validate_args("") is False

    def test_category(self):
        assert SubdomainTakeoverTool.category == ToolCategory.RECON_ACTIVE

    def test_no_approval_required(self):
        assert SubdomainTakeoverTool.requires_approval is False

    def test_always_available(self):
        assert SubdomainTakeoverTool().is_available() is True

    def test_fingerprints_not_empty(self):
        assert len(_TAKEOVER_FINGERPRINTS) >= 8

    def test_fingerprints_have_known_services(self):
        assert "github-pages" in _TAKEOVER_FINGERPRINTS
        assert "heroku" in _TAKEOVER_FINGERPRINTS
        assert "aws-s3" in _TAKEOVER_FINGERPRINTS

    @pytest.mark.asyncio
    async def test_run_fingerprint_detects_github_pages(self):
        tool = SubdomainTakeoverTool()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "There isn't a GitHub Pages site here. Are you lost?"

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=MagicMock(
                get=AsyncMock(return_value=mock_response)
            ))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_cm

            # Force fingerprint path by patching shutil.which to return None
            with patch("shutil.which", return_value=None):
                result = await tool.run("dangling.example.com")

        assert result.status == "success"
        assert any(f["service"] == "github-pages" for f in result.findings_raw)

    @pytest.mark.asyncio
    async def test_run_no_takeover_on_normal_page(self):
        tool = SubdomainTakeoverTool()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Welcome to Example!</body></html>"

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=MagicMock(
                get=AsyncMock(return_value=mock_response)
            ))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_cm

            with patch("shutil.which", return_value=None):
                result = await tool.run("normal.example.com")

        assert result.status == "success"
        assert result.findings_raw == []


# ── JsSecretsTool ─────────────────────────────────────────────────────────────

class TestJsSecretsTool:
    def test_validate_https(self):
        assert JsSecretsTool().validate_args("https://example.com") is True

    def test_validate_http(self):
        assert JsSecretsTool().validate_args("http://example.com") is True

    def test_rejects_bare_domain(self):
        assert JsSecretsTool().validate_args("example.com") is False

    def test_rejects_empty(self):
        assert JsSecretsTool().validate_args("") is False

    def test_category(self):
        assert JsSecretsTool.category == ToolCategory.SECRETS

    def test_no_approval_required(self):
        assert JsSecretsTool.requires_approval is False

    def test_always_available(self):
        assert JsSecretsTool().is_available() is True

    def test_secret_patterns_not_empty(self):
        assert len(_SECRET_PATTERNS) >= 8

    def test_aws_key_pattern(self):
        pattern = _SECRET_PATTERNS["aws_access_key"]
        assert pattern.search("AKIAIOSFODNN7EXAMPLE") is not None
        assert pattern.search("not-a-key") is None

    def test_github_token_pattern(self):
        pattern = _SECRET_PATTERNS["github_token"]
        assert pattern.search("ghp_" + "a" * 36) is not None
        assert pattern.search("ghu_" + "b" * 36) is not None

    def test_stripe_key_pattern(self):
        pattern = _SECRET_PATTERNS["stripe_key"]
        assert pattern.search("sk_live_" + "x" * 24) is not None
        assert pattern.search("pk_test_" + "y" * 24) is not None

    @pytest.mark.asyncio
    async def test_run_detects_aws_key_in_js(self):
        tool = JsSecretsTool()
        js_content = "var config = { key: 'AKIAIOSFODNN7EXAMPLE', secret: 'wJalrXUt' };"

        page_response = MagicMock()
        page_response.status_code = 200
        page_response.text = '<script src="/app.js"></script>'

        js_response = MagicMock()
        js_response.status_code = 200
        js_response.text = js_content

        call_count = 0

        async def fake_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if url.endswith(".js"):
                return js_response
            return page_response

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=MagicMock(get=fake_get))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_cm

            with patch("shutil.which", return_value=None):
                result = await tool.run("https://example.com")

        assert result.status == "success"
        aws_findings = [f for f in result.findings_raw if f["type"] == "aws_access_key"]
        assert len(aws_findings) >= 1
        assert aws_findings[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_run_no_js_files_returns_success(self):
        tool = JsSecretsTool()

        page_response = MagicMock()
        page_response.status_code = 200
        page_response.text = "<html><body>No scripts here</body></html>"

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=MagicMock(
                get=AsyncMock(return_value=page_response)
            ))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_cm

            with patch("shutil.which", return_value=None):
                result = await tool.run("https://example.com")

        assert result.status == "success"
        assert result.findings_raw == []


# ── H1 Program Scanner ────────────────────────────────────────────────────────

class TestH1ProgramScanner:
    @pytest.mark.asyncio
    async def test_fallback_returns_programs_when_no_creds(self, monkeypatch):
        monkeypatch.delenv("H1_USERNAME", raising=False)
        monkeypatch.delenv("H1_API_TOKEN", raising=False)

        from recon_agent.h1.program_scanner import fetch_programs
        programs = await fetch_programs()
        assert len(programs) >= 5

    @pytest.mark.asyncio
    async def test_fallback_sorted_by_roi_desc(self, monkeypatch):
        monkeypatch.delenv("H1_USERNAME", raising=False)
        monkeypatch.delenv("H1_API_TOKEN", raising=False)

        from recon_agent.h1.program_scanner import fetch_programs
        programs = await fetch_programs()
        scores = [p.roi_score for p in programs]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.asyncio
    async def test_top_programs_returns_n(self, monkeypatch):
        monkeypatch.delenv("H1_USERNAME", raising=False)
        monkeypatch.delenv("H1_API_TOKEN", raising=False)

        from recon_agent.h1.program_scanner import top_programs
        top = await top_programs(n=3)
        assert len(top) == 3

    def test_roi_score_range(self):
        from recon_agent.h1.program_scanner import _roi_score
        score = _roi_score(5000, 1000, 95, 0.5)
        assert 0.0 <= score <= 1.0

    def test_roi_score_higher_bounty_ranks_higher(self):
        from recon_agent.h1.program_scanner import _roi_score
        low = _roi_score(500, 100, 90)
        high = _roi_score(20000, 5000, 90)
        assert high > low

    def test_freshness_bonus_recent(self):
        from datetime import datetime, timezone, timedelta
        from recon_agent.h1.program_scanner import _freshness_bonus
        recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        assert _freshness_bonus(recent) == 1.0

    def test_freshness_bonus_old(self):
        from recon_agent.h1.program_scanner import _freshness_bonus
        assert _freshness_bonus("2020-01-01T00:00:00Z") == 0.0

    def test_freshness_bonus_none(self):
        from recon_agent.h1.program_scanner import _freshness_bonus
        assert _freshness_bonus(None) == 0.0

    def test_program_target_weekly_expected(self):
        from recon_agent.h1.program_scanner import ProgramTarget
        p = ProgramTarget(
            handle="test", name="Test", program_url="https://h1.com/test",
            min_bounty_critical=10000, min_bounty_high=2000,
            response_efficiency_pct=95, roi_score=0.8,
        )
        # ~714 from critical (10000/14) + ~571 from high (2000*2/7)
        assert p.weekly_expected_usd > 1000


# ── Batch runner parsing ──────────────────────────────────────────────────────

class TestBatchParsing:
    def test_parse_basic_line(self, tmp_path):
        f = tmp_path / "programs.txt"
        f.write_text("https://hackerone.com/acme  acme.com,*.acme.com\n")
        from recon_agent.cli.batch import parse_programs_file
        progs = parse_programs_file(f)
        assert len(progs) == 1
        assert progs[0].program_url == "https://hackerone.com/acme"
        assert "acme.com" in progs[0].in_scope

    def test_parse_with_out_scope(self, tmp_path):
        f = tmp_path / "programs.txt"
        f.write_text("https://hackerone.com/acme  acme.com  out:legacy.acme.com\n")
        from recon_agent.cli.batch import parse_programs_file
        progs = parse_programs_file(f)
        assert progs[0].out_of_scope == ["legacy.acme.com"]

    def test_parse_skips_comments(self, tmp_path):
        f = tmp_path / "programs.txt"
        f.write_text("# comment\nhttps://hackerone.com/beta  beta.com\n")
        from recon_agent.cli.batch import parse_programs_file
        progs = parse_programs_file(f)
        assert len(progs) == 1

    def test_parse_skips_blank_lines(self, tmp_path):
        f = tmp_path / "programs.txt"
        f.write_text("\n\nhttps://hackerone.com/beta  beta.com\n\n")
        from recon_agent.cli.batch import parse_programs_file
        progs = parse_programs_file(f)
        assert len(progs) == 1

    def test_parse_skips_incomplete_lines(self, tmp_path):
        f = tmp_path / "programs.txt"
        f.write_text("https://hackerone.com/acme\n")  # missing scope
        from recon_agent.cli.batch import parse_programs_file
        progs = parse_programs_file(f)
        assert len(progs) == 0


# ── Registry count ────────────────────────────────────────────────────────────

class TestRegistryWith30Tools:
    def test_total_30_tools(self):
        from recon_agent.tools.registry import build_default_registry
        registry = build_default_registry()
        assert len(registry.all_tools()) == 30

    def test_takeover_registered(self):
        from recon_agent.tools.registry import build_default_registry
        registry = build_default_registry()
        assert "takeover" in registry

    def test_jssecrets_registered(self):
        from recon_agent.tools.registry import build_default_registry
        registry = build_default_registry()
        assert "jssecrets" in registry

    def test_both_new_tools_always_available(self):
        from recon_agent.tools.recon.takeover import SubdomainTakeoverTool
        from recon_agent.tools.secrets.jssecrets import JsSecretsTool
        assert SubdomainTakeoverTool().is_available() is True
        assert JsSecretsTool().is_available() is True
