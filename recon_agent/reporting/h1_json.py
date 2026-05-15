from __future__ import annotations

import re
from typing import Any

from recon_agent.core.state import Finding, Severity

# Map our severity to H1's accepted values
_SEVERITY_MAP = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "informational",
}

_CWE_ID_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _extract_cwe_id(cwe: str | None) -> int | None:
    if not cwe:
        return None
    m = _CWE_ID_RE.search(cwe)
    return int(m.group(1)) if m else None


def _build_vulnerability_information(finding: Finding) -> str:
    """Build the H1 vulnerability_information markdown field."""
    lines = [
        "## Summary",
        "",
        finding.description,
        "",
        "## Steps To Reproduce",
        "",
    ]

    if finding.poc:
        lines.append(finding.poc)
    else:
        lines.append("1. [Reproduce manually — automated PoC not generated]")

    lines += [
        "",
        "## Supporting Material / Evidence",
        "",
        "```",
        finding.evidence[:4000],
        "```",
        "",
        "## Impact",
        "",
        finding.impact,
    ]

    if finding.remediation:
        lines += [
            "",
            "## Remediation",
            "",
            finding.remediation,
        ]

    return "\n".join(lines)


def finding_to_h1(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to an H1-compatible report dict."""
    report: dict[str, Any] = {
        "title": finding.title,
        "severity": _SEVERITY_MAP.get(finding.severity, "low"),
        "vulnerability_information": _build_vulnerability_information(finding),
        "asset": finding.asset,
        "source_tool": finding.source_tool,
        "confidence": finding.confidence,
    }

    cwe_id = _extract_cwe_id(finding.cwe)
    if cwe_id:
        report["weakness"] = {"id": cwe_id}

    if finding.cvss:
        report["cvss_score"] = finding.cvss

    return report


def findings_to_h1_bundle(findings: list[Finding], program_url: str) -> dict[str, Any]:
    """Build a full H1 JSON bundle for all confirmed findings."""
    return {
        "program_url": program_url,
        "reports": [finding_to_h1(f) for f in findings if not f.false_positive],
        "total": len([f for f in findings if not f.false_positive]),
    }
