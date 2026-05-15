"""Tests for Phase 3: dnsx, crtsh, naabu, trivy, prowler, H1 JSON, availability."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from recon_agent.tools.recon.dnsx import DnsxTool
from recon_agent.tools.recon.crtsh import CrtshTool
from recon_agent.tools.recon.naabu import NaabuTool
from recon_agent.tools.cloud.trivy import TrivyTool
from recon_agent.tools.cloud.prowler import ProwlerTool
from recon_agent.core.state import ToolCategory, Finding, Severity
from recon_agent.reporting.h1_json import (
    finding_to_h1,
    findings_to_h1_bundle,
    _extract_cwe_id,
    _build_vulnerability_information,
)
from recon_agent.tools.registry import build_default_registry


# ── dnsx ──────────────────────────────────────────────────────────────────────

class TestDnsxTool:
    def test_validate_domain(self):
        assert DnsxTool().validate_args("example.com") is True

    def test_validate_subdomain_list(self):
        assert DnsxTool().validate_args("sub.example.com,api.example.com") is True

    def test_validate_empty_rejected(self):
        assert DnsxTool().validate_args("") is False

    def test_category(self):
        assert DnsxTool.category == ToolCategory.RECON_ACTIVE

    def test_no_approval(self):
        assert DnsxTool.requires_approval is False


# ── crtsh ─────────────────────────────────────────────────────────────────────

class TestCrtshTool:
    def test_validate_domain(self):
        assert CrtshTool().validate_args("example.com") is True

    def test_validate_wildcard(self):
        assert CrtshTool().validate_args("*.example.com") is True

    def test_rejects_ip(self):
        assert CrtshTool().validate_args("192.168.1.1") is False

    def test_always_available(self):
        assert CrtshTool().is_available() is True

    def test_category(self):
        assert CrtshTool.category == ToolCategory.RECON_PASSIVE

    @pytest.mark.asyncio
    async def test_run_returns_subdomains_on_mock(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "api.example.com\nwww.example.com"},
            {"name_value": "mail.example.com"},
        ]

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(
                return_value=MagicMock(get=AsyncMock(return_value=mock_response))
            )
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await CrtshTool().run("example.com")

        assert result.status == "success"
        subs = [e["subdomain"] for e in result.findings_raw]
        assert "api.example.com" in subs
        assert "www.example.com" in subs
        assert "mail.example.com" in subs


# ── naabu ─────────────────────────────────────────────────────────────────────

class TestNaabuTool:
    def test_validate_domain(self):
        assert NaabuTool().validate_args("example.com") is True

    def test_validate_ip(self):
        assert NaabuTool().validate_args("192.168.1.1") is True

    def test_validate_url(self):
        assert NaabuTool().validate_args("https://example.com") is True

    def test_rejects_empty(self):
        assert NaabuTool().validate_args("") is False

    def test_category(self):
        assert NaabuTool.category == ToolCategory.INFRA_SCAN


# ── trivy ─────────────────────────────────────────────────────────────────────

class TestTrivyTool:
    def test_validate_any_target(self):
        assert TrivyTool().validate_args("nginx:latest") is True
        assert TrivyTool().validate_args("https://github.com/user/repo") is True
        assert TrivyTool().validate_args("/path/to/code") is True

    def test_rejects_empty(self):
        assert TrivyTool().validate_args("") is False

    def test_category(self):
        assert TrivyTool.category == ToolCategory.CLOUD_SCAN

    def test_no_approval(self):
        assert TrivyTool.requires_approval is False


# ── prowler ───────────────────────────────────────────────────────────────────

class TestProwlerTool:
    def test_validate_aws_provider(self):
        assert ProwlerTool().validate_args("aws-account", provider="aws") is True

    def test_validate_azure_provider(self):
        assert ProwlerTool().validate_args("my-sub", provider="azure") is True

    def test_rejects_invalid_provider(self):
        assert ProwlerTool().validate_args("target", provider="unknown") is False

    def test_category(self):
        assert ProwlerTool.category == ToolCategory.CLOUD_SCAN


# ── H1 JSON ───────────────────────────────────────────────────────────────────

def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        title="Reflected XSS in search parameter",
        severity=Severity.HIGH,
        asset="https://example.com/search?q=test",
        description="The `q` parameter reflects user input without sanitization.",
        evidence='HTTP/1.1 200 OK\n<script>alert(1)</script>',
        poc="1. Navigate to https://example.com/search?q=<script>alert(1)</script>\n2. Observe alert box.",
        impact="Attacker can steal session cookies or perform actions on behalf of the victim.",
        remediation="Encode output using htmlspecialchars() or equivalent.",
        cwe="CWE-79",
        cvss=6.1,
        source_tool="dalfox",
        confidence=0.95,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestH1Json:
    def test_finding_to_h1_basic(self):
        finding = _make_finding()
        h1 = finding_to_h1(finding)
        assert h1["title"] == "Reflected XSS in search parameter"
        assert h1["severity"] == "high"
        assert h1["weakness"] == {"id": 79}
        assert h1["cvss_score"] == 6.1

    def test_severity_mapping_critical(self):
        finding = _make_finding(severity=Severity.CRITICAL)
        h1 = finding_to_h1(finding)
        assert h1["severity"] == "critical"

    def test_severity_mapping_info(self):
        finding = _make_finding(severity=Severity.INFO)
        h1 = finding_to_h1(finding)
        assert h1["severity"] == "informational"

    def test_vulnerability_information_contains_sections(self):
        finding = _make_finding()
        h1 = finding_to_h1(finding)
        vuln_info = h1["vulnerability_information"]
        assert "## Summary" in vuln_info
        assert "## Steps To Reproduce" in vuln_info
        assert "## Impact" in vuln_info
        assert "## Supporting Material" in vuln_info

    def test_poc_included_in_reproduce(self):
        finding = _make_finding()
        h1 = finding_to_h1(finding)
        assert "Navigate to" in h1["vulnerability_information"]

    def test_no_cwe_omits_weakness(self):
        finding = _make_finding(cwe=None)
        h1 = finding_to_h1(finding)
        assert "weakness" not in h1

    def test_no_cvss_omits_score(self):
        finding = _make_finding(cvss=None)
        h1 = finding_to_h1(finding)
        assert "cvss_score" not in h1

    def test_findings_to_h1_bundle_excludes_fp(self):
        f1 = _make_finding(title="Real XSS")
        f2 = _make_finding(title="False Positive", false_positive=True)
        bundle = findings_to_h1_bundle([f1, f2], "https://hackerone.com/test")
        assert bundle["total"] == 1
        assert bundle["reports"][0]["title"] == "Real XSS"

    def test_bundle_program_url(self):
        bundle = findings_to_h1_bundle([], "https://hackerone.com/test")
        assert bundle["program_url"] == "https://hackerone.com/test"

    def test_extract_cwe_id(self):
        assert _extract_cwe_id("CWE-79") == 79
        assert _extract_cwe_id("CWE-89") == 89
        assert _extract_cwe_id(None) is None
        assert _extract_cwe_id("no cwe here") is None

    def test_cwe_case_insensitive(self):
        assert _extract_cwe_id("cwe-22") == 22


# ── Tool availability ─────────────────────────────────────────────────────────

class TestToolAvailability:
    def test_is_available_returns_bool(self):
        from recon_agent.tools.recon.subfinder import SubfinderTool
        result = SubfinderTool().is_available()
        assert isinstance(result, bool)

    def test_crtsh_always_available(self):
        assert CrtshTool().is_available() is True

    def test_registry_available_tools_subset(self):
        registry = build_default_registry()
        available = registry.available_tools()
        all_tools = registry.all_tools()
        assert len(available) <= len(all_tools)
        for tool in available:
            assert tool.is_available() is True

    def test_registry_total_28_tools(self):
        registry = build_default_registry()
        assert len(registry.all_tools()) == 28
