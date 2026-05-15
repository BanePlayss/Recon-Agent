from __future__ import annotations

from typing import Any

import structlog

from recon_agent.core.state import AgentState, Finding, Severity, ActionLog
from recon_agent.llm.gemini import GeminiClient
from recon_agent.llm.prompts import render_planner, render_observer
from recon_agent.tools.base import ToolResult

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
    def __init__(self, client: GeminiClient) -> None:
        self._client = client

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
        result, cost = await self._client.generate_json(prompt, temperature=0.3)

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
        result, cost = await self._client.generate_json(prompt, temperature=0.1)

        logger.info(
            "observer.result",
            new_subdomains=len(result.get("new_subdomains", [])),
            new_findings=len(result.get("findings", [])),
            summary=result.get("summary", "")[:100],
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
