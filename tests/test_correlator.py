import pytest
from unittest.mock import AsyncMock, MagicMock

from recon_agent.core.correlator import Correlator
from recon_agent.core.state import AgentState, Finding, Severity, AttackChain


def _make_finding(title: str, severity: Severity, asset: str = "https://example.com") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        asset=asset,
        description="test",
        evidence="test output",
        impact="test impact",
        remediation="test fix",
        source_tool="nuclei",
        confidence=0.9,
    )


def _make_state(findings: list[Finding]) -> AgentState:
    state = AgentState(
        program_url="https://hackerone.com/test",
        targets_in_scope=["example.com"],
    )
    for f in findings:
        state.findings.append(f)
    return state


class TestCorrelator:
    @pytest.mark.asyncio
    async def test_skip_when_fewer_than_2_findings(self):
        router = MagicMock()
        correlator = Correlator(router)
        state = _make_state([_make_finding("XSS", Severity.HIGH)])
        cost = await correlator.correlate(state)
        assert cost == 0.0
        router.correlate.assert_not_called()

    @pytest.mark.asyncio
    async def test_marks_false_positives(self):
        f1 = _make_finding("XSS", Severity.HIGH)
        f2 = _make_finding("SQLi", Severity.CRITICAL)
        state = _make_state([f1, f2])

        router = MagicMock()
        router.correlate = AsyncMock(return_value=(
            {
                "false_positive_ids": [f1.id],
                "attack_chains": [],
                "priority_order": [],
                "summary": "test",
            },
            0.001,
        ))

        correlator = Correlator(router)
        cost = await correlator.correlate(state)

        assert cost == 0.001
        assert state.findings[0].false_positive is True
        assert state.findings[1].false_positive is False

    @pytest.mark.asyncio
    async def test_adds_attack_chains(self):
        f1 = _make_finding("XSS", Severity.HIGH)
        f2 = _make_finding("CSRF", Severity.MEDIUM)
        f3 = _make_finding("SQLi", Severity.CRITICAL)
        state = _make_state([f1, f2, f3])

        router = MagicMock()
        router.correlate = AsyncMock(return_value=(
            {
                "false_positive_ids": [],
                "attack_chains": [
                    {
                        "title": "XSS + CSRF Account Takeover",
                        "finding_ids": [f1.id, f2.id],
                        "combined_severity": "critical",
                        "description": "Chain description",
                        "poc": "1. Exploit XSS to steal CSRF token...",
                    }
                ],
                "priority_order": [f3.id, f1.id, f2.id],
                "summary": "critical attack surface",
            },
            0.002,
        ))

        correlator = Correlator(router)
        await correlator.correlate(state)

        assert len(state.attack_chains) == 1
        chain = state.attack_chains[0]
        assert chain.title == "XSS + CSRF Account Takeover"
        assert chain.combined_severity == Severity.CRITICAL
        assert f1.id in chain.finding_ids

    @pytest.mark.asyncio
    async def test_handles_invalid_severity_gracefully(self):
        f1 = _make_finding("XSS", Severity.HIGH)
        f2 = _make_finding("SQLi", Severity.CRITICAL)
        state = _make_state([f1, f2])

        router = MagicMock()
        router.correlate = AsyncMock(return_value=(
            {
                "false_positive_ids": [],
                "attack_chains": [
                    {
                        "title": "Chain with bad severity",
                        "finding_ids": [f1.id],
                        "combined_severity": "super_critical",  # invalid
                        "description": "test",
                    }
                ],
                "priority_order": [],
                "summary": "test",
            },
            0.001,
        ))

        correlator = Correlator(router)
        await correlator.correlate(state)
        assert len(state.attack_chains) == 1
        assert state.attack_chains[0].combined_severity == Severity.HIGH


class TestAttackChainModel:
    def test_attack_chain_creation(self):
        chain = AttackChain(
            title="Test chain",
            finding_ids=["id1", "id2"],
            combined_severity=Severity.CRITICAL,
            description="Description",
            poc="Steps",
        )
        assert chain.combined_severity == Severity.CRITICAL
        assert len(chain.finding_ids) == 2

    def test_attack_chain_no_poc(self):
        chain = AttackChain(
            title="Test",
            finding_ids=[],
            combined_severity=Severity.LOW,
            description="desc",
        )
        assert chain.poc is None


class TestAgentStatePhase2:
    def test_real_findings_excludes_fp(self):
        state = _make_state([])
        f1 = _make_finding("Real", Severity.HIGH)
        f2 = _make_finding("FP", Severity.MEDIUM)
        f2.false_positive = True
        state.findings = [f1, f2]
        assert len(state.real_findings()) == 1
        assert state.real_findings()[0].title == "Real"

    def test_deep_analyzed_flag(self):
        f = _make_finding("Test", Severity.CRITICAL)
        assert f.deep_analyzed is False
        f.deep_analyzed = True
        assert f.deep_analyzed is True
