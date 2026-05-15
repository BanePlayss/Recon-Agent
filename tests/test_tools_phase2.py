import pytest
from pathlib import Path

from recon_agent.tools.recon.amass import AmassTool
from recon_agent.tools.recon.nmap_tool import NmapTool
from recon_agent.tools.web.ffuf import FfufTool, _find_wordlist
from recon_agent.tools.web.katana import KatanaTool
from recon_agent.tools.web.nikto import NiktoTool
from recon_agent.tools.web.wpscan import WpscanTool
from recon_agent.tools.exploit.sqlmap import SqlmapTool
from recon_agent.tools.exploit.dalfox import DalfoxTool
from recon_agent.tools.secrets.trufflehog import TrufflehogTool
from recon_agent.tools.secrets.gitleaks import GitleaksTool
from recon_agent.core.state import ToolCategory


class TestAmassTool:
    def test_validate_domain(self):
        assert AmassTool().validate_args("example.com") is True

    def test_validate_wildcard(self):
        assert AmassTool().validate_args("*.example.com") is True

    def test_rejects_ip(self):
        assert AmassTool().validate_args("10.0.0.1") is False

    def test_category(self):
        assert AmassTool.category == ToolCategory.RECON_PASSIVE


class TestNmapTool:
    def test_validate_domain(self):
        assert NmapTool().validate_args("example.com") is True

    def test_validate_ip(self):
        assert NmapTool().validate_args("192.168.1.1") is True

    def test_validate_url(self):
        assert NmapTool().validate_args("https://example.com") is True

    def test_rejects_empty(self):
        assert NmapTool().validate_args("") is False

    def test_category(self):
        assert NmapTool.category == ToolCategory.INFRA_SCAN

    def test_no_approval_required(self):
        assert NmapTool.requires_approval is False


class TestFfufTool:
    def test_validate_http(self):
        assert FfufTool().validate_args("http://example.com") is True

    def test_validate_https(self):
        assert FfufTool().validate_args("https://example.com") is True

    def test_rejects_bare_domain(self):
        assert FfufTool().validate_args("example.com") is False

    def test_rejects_empty(self):
        assert FfufTool().validate_args("") is False

    def test_category(self):
        assert FfufTool.category == ToolCategory.WEB_SCAN

    def test_find_wordlist_nonexistent(self):
        result = _find_wordlist("/nonexistent/path.txt")
        # Returns None or a system wordlist if installed
        assert result is None or Path(result).exists()


class TestKatanaTool:
    def test_validate_https(self):
        assert KatanaTool().validate_args("https://example.com") is True

    def test_rejects_domain(self):
        assert KatanaTool().validate_args("example.com") is False

    def test_category(self):
        assert KatanaTool.category == ToolCategory.WEB_SCAN


class TestNiktoTool:
    def test_validate_https(self):
        assert NiktoTool().validate_args("https://example.com") is True

    def test_validate_http(self):
        assert NiktoTool().validate_args("http://example.com") is True

    def test_rejects_domain(self):
        assert NiktoTool().validate_args("example.com") is False

    def test_category(self):
        assert NiktoTool.category == ToolCategory.WEB_SCAN


class TestWpscanTool:
    def test_validate_https(self):
        assert WpscanTool().validate_args("https://blog.example.com") is True

    def test_rejects_domain(self):
        assert WpscanTool().validate_args("example.com") is False

    def test_category(self):
        assert WpscanTool.category == ToolCategory.WEB_SCAN


class TestSqlmapTool:
    def test_validate_url_with_param(self):
        assert SqlmapTool().validate_args("https://example.com/page?id=1") is True

    def test_validate_https(self):
        assert SqlmapTool().validate_args("https://example.com/login") is True

    def test_rejects_bare_domain(self):
        assert SqlmapTool().validate_args("example.com") is False

    def test_category(self):
        assert SqlmapTool.category == ToolCategory.EXPLOIT

    def test_requires_approval(self):
        assert SqlmapTool.requires_approval is True


class TestDalfoxTool:
    def test_validate_url(self):
        assert DalfoxTool().validate_args("https://example.com/search?q=test") is True

    def test_rejects_domain(self):
        assert DalfoxTool().validate_args("example.com") is False

    def test_category(self):
        assert DalfoxTool.category == ToolCategory.EXPLOIT

    def test_requires_approval(self):
        assert DalfoxTool.requires_approval is True


class TestTrufflehogTool:
    def test_validate_git_url(self):
        assert TrufflehogTool().validate_args("https://github.com/example/repo") is True

    def test_validate_git_url_dotgit(self):
        assert TrufflehogTool().validate_args("https://github.com/example/repo.git") is True

    def test_validate_local_path(self):
        assert TrufflehogTool().validate_args("/tmp") is True

    def test_rejects_bare_domain(self):
        assert TrufflehogTool().validate_args("example.com") is False

    def test_category(self):
        assert TrufflehogTool.category == ToolCategory.SECRETS

    def test_no_approval(self):
        assert TrufflehogTool.requires_approval is False


class TestGitleaksTool:
    def test_validate_existing_path(self, tmp_path):
        assert GitleaksTool().validate_args(str(tmp_path)) is True

    def test_rejects_nonexistent_path(self):
        assert GitleaksTool().validate_args("/nonexistent/path/xyz") is False

    def test_category(self):
        assert GitleaksTool.category == ToolCategory.SECRETS


class TestFullRegistry:
    def test_all_phase2_tools_registered(self):
        from recon_agent.tools.registry import build_default_registry
        registry = build_default_registry()
        expected = [
            "subfinder", "amass", "httpx", "nmap",
            "nuclei", "ffuf", "katana", "nikto", "wpscan",
            "sqlmap", "dalfox", "trufflehog", "gitleaks",
        ]
        for name in expected:
            assert name in registry, f"Tool '{name}' not registered"

    def test_registry_has_13_tools(self):
        from recon_agent.tools.registry import build_default_registry
        registry = build_default_registry()
        assert len(registry.all_tools()) == 13
