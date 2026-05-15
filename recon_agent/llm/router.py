from __future__ import annotations

from typing import Any, TYPE_CHECKING

import structlog

from recon_agent.core.state import AgentState, Finding, Severity, ActionLog
from recon_agent.llm.gemini import GeminiClient
from recon_agent.llm.prompts import (
    render_planner,
    render_observer,
    render_correlator,
    render_deep_analysis,
)
from recon_agent.tools.base import ToolResult

if TYPE_CHECKING:
    from recon_agent.llm.claude import ClaudeClient

logger = structlog.get_logger(__name__)


class PlannerAction:
    def __init__(
        self,
        reasoning: str,
        action: str,
        target: str,
        kwargs: dict[str, Any],
        stop: bool = False,
    ) -> None:
        self.reasoning = reasoning
        self.action = action
        self.target = target
        self.kwargs = kwargs
        self.stop = stop


class LLMRouter:
    def __init__(
        self,
        gemini_client: GeminiClient,
        claude_client: "ClaudeClient | None" = None,
    ) -> None:
        self._gemini = gemini_client
        self._claude = claude_client

    async def plan(
        self,
        state: AgentState,
        available_tools: list[Any],
        depth_mode: str,
        agent_mode: str,
        max_iterations: int,
        max_hours: float,
        max_cost_usd: float,
    ) -> tuple[PlannerAction, float]:
        context = {
            "state": state,
            "available_tools": available_tools,
            "depth_mode": depth_mode,
            "agent_mode": agent_mode,
            "max_iterations": max_iterations,
            "max_hours": max_hours,
            "max_cost_usd": max_cost_usd,
        }
        prompt = render_planner(context)
        result, cost = await self._gemini.generate_json(prompt, temperature=0.3)

        if result.get("stop"):
            return PlannerAction(
                reasoning=result.get("reasoning", "Agent decided to stop"),
                action="",
                target="",
                kwargs={},
                stop=True,
            ), cost

        action = PlannerAction(
            reasoning=result.get("reasoning", ""),
            action=result.get("action", ""),
            target=result.get("target", ""),
            kwargs=result.get("kwargs", {}),
            stop=False,
        )

        logger.info(
            "planner.decision",
            action=action.action,
            target=action.target[:80],
            reasoning=action.reasoning[:120],
        )
        return action, cost

    async def observe(
        self,
        tool_result: ToolResult,
        state: AgentState,
    ) -> tuple[dict[str, Any], float]:
        context = {"tool_result": tool_result, "state": state}
        prompt = render_observer(context)
        result, cost = await self._gemini.generate_json(prompt, temperature=0.1)

        logger.info(
            "observer.result",
            new_subdomains=len(result.get("new_subdomains", [])),
            new_findings=len(result.get("findings", [])),
            summary=result.get("summary", "")[:100],
        )
        return result, cost

    async def deep_analyze(
        self, finding: Finding, state: AgentState
    ) -> tuple[Finding, float]:
        """
        Use Claude to enrich a critical/high finding.
        Falls back to Gemini if Claude is unavailable.
        Returns the updated Finding and cost.
        """
        context = {"finding": finding, "state": state}
        prompt = render_deep_analysis(context)

        if self._claude:
            result, cost = await self._claude.deep_analyze(prompt)
        else:
            result, cost = await self._gemini.generate_json(prompt, temperature=0.1)

        if result.get("is_false_positive"):
            finding.false_positive = True
            logger.info(
                "deep_analysis.false_positive",
                title=finding.title,
                reason=result.get("false_positive_reason", ""),
            )
            finding.deep_analyzed = True
            return finding, cost

        severity_str = result.get("validated_severity", finding.severity.value).lower()
        try:
            finding.severity = Severity(severity_str)
        except ValueError:
            pass

        finding.title = result.get("validated_title", finding.title)
        finding.description = result.get("description", finding.description)
        finding.poc = result.get("poc", finding.poc)
        finding.impact = result.get("impact", finding.impact)
        finding.remediation = result.get("remediation", finding.remediation)
        finding.cwe = result.get("cwe", finding.cwe)
        finding.cvss = result.get("cvss", finding.cvss)
        finding.confidence = float(result.get("confidence", finding.confidence))
        finding.deep_analyzed = True

        logger.info(
            "deep_analysis.done",
            title=finding.title,
            severity=finding.severity,
            cvss=finding.cvss,
        )
        return finding, cost

    async def correlate(
        self, state: AgentState
    ) -> tuple[dict[str, Any], float]:
        context = {
            "findings": state.real_findings(),
            "state": state,
        }
        prompt = render_correlator(context)
        result, cost = await self._gemini.generate_json(prompt, temperature=0.2)

        logger.info(
            "correlator.result",
            chains=len(result.get("attack_chains", [])),
            fp_ids=len(result.get("false_positive_ids", [])),
        )
        return result, cost

    def parse_findings(self, observation: dict[str, Any], source_tool: str) -> list[Finding]:
        findings = []
        for raw in observation.get("findings", []):
            try:
                severity_str = raw.get("severity", "info").lower()
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.INFO

                finding = Finding(
                    title=raw["title"],
                    severity=severity,
                    asset=raw.get("asset", ""),
                    description=raw.get("description", ""),
                    evidence=raw.get("evidence", ""),
                    poc=raw.get("poc"),
                    impact=raw.get("impact", ""),
                    remediation=raw.get("remediation", ""),
                    cwe=raw.get("cwe"),
                    cvss=raw.get("cvss"),
                    source_tool=source_tool,
                    confidence=float(raw.get("confidence", 0.7)),
                )
                findings.append(finding)
            except (KeyError, ValueError, TypeError) as e:
                logger.warning("router.parse_finding_error", error=str(e), raw=raw)
        return findings
