"""Tests for the H1 report auto-drafter."""
from __future__ import annotations

import pytest
from recon_agent.core.state import Finding, Severity
from recon_agent.reporting.drafter import draft, draft_to_file


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        title="AWS Access Key Exposed in CDN JavaScript",
        severity=Severity.CRITICAL,
        asset="https://cdn.example.com/app.min.js",
        description="An AWS access key and secret key were found hardcoded in a publicly accessible JavaScript bundle.",
        evidence="AKIAIOSFODNN7EXAMPLE\naws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        poc="1. Navigate to https://cdn.example.com/app.min.js\n2. Search for 'AKIA'\n3. Observe the hardcoded AWS access key.",
        impact="An attacker can use these credentials to access AWS resources.",
        remediation="Rotate the exposed credentials immediately. Move secrets to environment variables or AWS Secrets Manager.",
        cwe="CWE-798",
        cvss=9.8,
        source_tool="jssecrets",
        confidence=0.97,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestDraft:
    def test_draft_contains_title(self):
        f = _make_finding()
        report = draft(f)
        assert "AWS Access Key Exposed" in report

    def test_draft_contains_severity(self):
        f = _make_finding()
        report = draft(f)
        assert "Critical" in report

    def test_draft_contains_asset(self):
        f = _make_finding()
        report = draft(f)
        assert "cdn.example.com" in report

    def test_draft_contains_cvss(self):
        f = _make_finding()
        report = draft(f)
        assert "9.8" in report

    def test_draft_contains_cwe(self):
        f = _make_finding()
        report = draft(f)
        assert "CWE-798" in report

    def test_draft_contains_summary_section(self):
        f = _make_finding()
        report = draft(f)
        assert "## Summary" in report

    def test_draft_contains_steps_section(self):
        f = _make_finding()
        report = draft(f)
        assert "## Steps To Reproduce" in report

    def test_draft_contains_impact_section(self):
        f = _make_finding()
        report = draft(f)
        assert "## Impact" in report

    def test_draft_contains_evidence_section(self):
        f = _make_finding()
        report = draft(f)
        assert "## Supporting Material" in report

    def test_draft_contains_remediation_section(self):
        f = _make_finding()
        report = draft(f)
        assert "## Remediation" in report

    def test_draft_includes_poc_steps(self):
        f = _make_finding()
        report = draft(f)
        assert "Navigate to" in report
        assert "Search for" in report

    def test_draft_includes_evidence_snippet(self):
        f = _make_finding()
        report = draft(f)
        assert "AKIAIOSFODNN7EXAMPLE" in report

    def test_draft_without_poc_uses_placeholder(self):
        f = _make_finding(poc=None)
        report = draft(f)
        assert "Steps To Reproduce" in report

    def test_draft_without_cvss_shows_range(self):
        f = _make_finding(cvss=None)
        report = draft(f)
        assert "9.0" in report  # CRITICAL range

    def test_draft_high_severity_range(self):
        f = _make_finding(severity=Severity.HIGH, cvss=None)
        report = draft(f)
        assert "7.0" in report

    def test_draft_without_cwe_no_cwe_text(self):
        f = _make_finding(cwe=None)
        report = draft(f)
        assert "CWE" not in report

    def test_draft_program_url_included(self):
        f = _make_finding()
        report = draft(f, program_url="https://hackerone.com/acme")
        assert "hackerone.com/acme" in report

    def test_draft_jssecrets_uses_specific_impact(self):
        f = _make_finding(source_tool="jssecrets", impact="")
        report = draft(f)
        assert "third-party service" in report or "credential" in report.lower()

    def test_draft_takeover_uses_specific_impact(self):
        f = _make_finding(source_tool="takeover", impact="")
        report = draft(f)
        assert "subdomain" in report.lower() or "arbitrary content" in report.lower()

    def test_draft_timestamp_included(self):
        f = _make_finding()
        report = draft(f)
        assert "recon-agent" in report

    def test_draft_returns_string(self):
        f = _make_finding()
        assert isinstance(draft(f), str)

    def test_draft_to_file_creates_file(self, tmp_path):
        f = _make_finding()
        path = str(tmp_path / "report.md")
        result = draft_to_file(f, path)
        from pathlib import Path
        assert Path(result).exists()
        assert "AWS Access Key" in Path(result).read_text()

    def test_draft_confidence_shown(self):
        f = _make_finding(confidence=0.97)
        report = draft(f)
        assert "97" in report

    def test_draft_tool_name_shown(self):
        f = _make_finding(source_tool="jssecrets")
        report = draft(f)
        assert "jssecrets" in report

    def test_draft_info_severity(self):
        f = _make_finding(severity=Severity.INFO)
        report = draft(f)
        assert "Informational" in report

    def test_draft_medium_severity(self):
        f = _make_finding(severity=Severity.MEDIUM)
        report = draft(f)
        assert "Medium" in report

    def test_draft_evidence_truncated_at_3000(self):
        f = _make_finding(evidence="X" * 5000)
        report = draft(f)
        assert "X" * 4000 not in report  # truncated
