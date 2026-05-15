"""Tests for tools added from hackingtool reference."""
import pytest
from pathlib import Path

from recon_agent.tools.web.wafw00f import Wafw00fTool
from recon_agent.tools.web.testssl import TestsslTool, _find_binary
from recon_agent.tools.web.arjun import ArjunTool
from recon_agent.tools.web.gobuster import GobusterTool
from recon_agent.tools.recon.masscan import MasscanTool
from recon_agent.tools.recon.theharvester import TheHarvesterTool
from recon_agent.tools.secrets.secretfinder import SecretFinderTool
from recon_agent.tools.exploit.xsstrike import XSStrikeTool
from recon_agent.tools.exploit.nosqlmap import NoSQLMapTool
from recon_agent.tools.exploit.commix import CommixTool
from recon_agent.core.state import ToolCategory


class TestWafw00fTool:
    def test_validate_https(self):
        assert Wafw00fTool().validate_args("https://example.com") is True

    def test_validate_http(self):
        assert Wafw00fTool().validate_args("http://example.com") is True

    def test_rejects_domain(self):
        assert Wafw00fTool().validate_args("example.com") is False

    def test_category(self):
        assert Wafw00fTool.category == ToolCategory.RECON_ACTIVE

    def test_no_approval_required(self):
        assert Wafw00fTool.requires_approval is False


class TestTestsslTool:
    def test_validate_host(self):
        assert TestsslTool().validate_args("example.com") is True

    def test_validate_url_stripped(self):
        assert TestsslTool().validate_args("https://example.com") is True

    def test_rejects_empty(self):
        assert TestsslTool().validate_args("") is False

    def test_category(self):
        assert TestsslTool.category == ToolCategory.WEB_SCAN

    def test_find_binary_returns_none_or_string(self):
        result = _find_binary()
        assert result is None or isinstance(result, str)


class TestArjunTool:
    def test_validate_https(self):
        assert ArjunTool().validate_args("https://example.com/api") is True

    def test_rejects_domain(self):
        assert ArjunTool().validate_args("example.com") is False

    def test_rejects_empty(self):
        assert ArjunTool().validate_args("") is False

    def test_category(self):
        assert ArjunTool.category == ToolCategory.WEB_SCAN

    def test_no_approval(self):
        assert ArjunTool.requires_approval is False


class TestGobusterTool:
    def test_validate_dir_mode(self):
        assert GobusterTool().validate_args("https://example.com", mode="dir") is True

    def test_validate_dns_mode(self):
        assert GobusterTool().validate_args("example.com", mode="dns") is True

    def test_validate_vhost_mode(self):
        assert GobusterTool().validate_args("https://example.com", mode="vhost") is True

    def test_rejects_invalid_mode(self):
        assert GobusterTool().validate_args("https://example.com", mode="exploit") is False

    def test_dir_rejects_bare_domain(self):
        assert GobusterTool().validate_args("example.com", mode="dir") is False

    def test_category(self):
        assert GobusterTool.category == ToolCategory.WEB_SCAN


class TestMasscanTool:
    def test_validate_ip(self):
        assert MasscanTool().validate_args("192.168.1.0/24") is True

    def test_validate_domain(self):
        assert MasscanTool().validate_args("example.com") is True

    def test_validate_url(self):
        assert MasscanTool().validate_args("https://example.com") is True

    def test_rejects_empty(self):
        assert MasscanTool().validate_args("") is False

    def test_category(self):
        assert MasscanTool.category == ToolCategory.INFRA_SCAN

    def test_no_approval(self):
        assert MasscanTool.requires_approval is False


class TestTheHarvesterTool:
    def test_validate_domain(self):
        assert TheHarvesterTool().validate_args("example.com") is True

    def test_validate_subdomain(self):
        assert TheHarvesterTool().validate_args("api.example.com") is True

    def test_validate_wildcard(self):
        assert TheHarvesterTool().validate_args("*.example.com") is True

    def test_rejects_ip(self):
        # IPs don't match FQDN pattern
        assert TheHarvesterTool().validate_args("192.168.1.1") is False

    def test_category(self):
        assert TheHarvesterTool.category == ToolCategory.RECON_PASSIVE


class TestSecretFinderTool:
    def test_validate_https(self):
        assert SecretFinderTool().validate_args("https://example.com/app.js") is True

    def test_rejects_domain(self):
        assert SecretFinderTool().validate_args("example.com") is False

    def test_category(self):
        assert SecretFinderTool.category == ToolCategory.SECRETS


class TestXSStrikeTool:
    def test_validate_url(self):
        assert XSStrikeTool().validate_args("https://example.com/search?q=test") is True

    def test_rejects_domain(self):
        assert XSStrikeTool().validate_args("example.com") is False

    def test_category(self):
        assert XSStrikeTool.category == ToolCategory.EXPLOIT

    def test_requires_approval(self):
        assert XSStrikeTool.requires_approval is True


class TestNoSQLMapTool:
    def test_validate_url(self):
        assert NoSQLMapTool().validate_args("https://example.com/api") is True

    def test_rejects_domain(self):
        assert NoSQLMapTool().validate_args("example.com") is False

    def test_category(self):
        assert NoSQLMapTool.category == ToolCategory.EXPLOIT

    def test_requires_approval(self):
        assert NoSQLMapTool.requires_approval is True


class TestCommixTool:
    def test_validate_url(self):
        assert CommixTool().validate_args("https://example.com/page?cmd=test") is True

    def test_rejects_domain(self):
        assert CommixTool().validate_args("example.com") is False

    def test_category(self):
        assert CommixTool.category == ToolCategory.EXPLOIT

    def test_requires_approval(self):
        assert CommixTool.requires_approval is True


class TestFullRegistryHackingtool:
    def test_all_23_tools_registered(self):
        from recon_agent.tools.registry import build_default_registry
        registry = build_default_registry()
        expected = [
            # recon passive
            "subfinder", "amass", "theHarvester",
            # recon active
            "httpx", "wafw00f",
            # infra
            "nmap", "masscan",
            # web
            "nuclei", "ffuf", "katana", "nikto", "wpscan",
            "testssl", "arjun", "gobuster",
            # exploit
            "sqlmap", "dalfox", "xsstrike", "nosqlmap", "commix",
            # secrets
            "trufflehog", "gitleaks", "secretfinder",
        ]
        for name in expected:
            assert name in registry, f"Tool '{name}' not in registry"

    def test_total_tool_count_at_least_23(self):
        from recon_agent.tools.registry import build_default_registry
        registry = build_default_registry()
        assert len(registry.all_tools()) >= 23
