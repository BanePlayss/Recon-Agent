from __future__ import annotations

from typing import Any

import structlog

from recon_agent.core.state import AgentState, AttackChain, Finding, Severity

logger = structlog.get_logger(__name__)


class Correlator:
    """Runs after the agent loop to find attack chains and flag false positives."""

    def __init__(self, llm_router: Any) -> None:
        self._router = llm_router

    async def correlate(self, state: AgentState) -> float:
        """
        Analyze all findings for correlations.
        Updates state.attack_chains and marks false positives.
        Returns LLM cost.
        """
        real_findings = [f for f in state.findings if not f.false_positive]
        if len(real_findings) < 2:
            logger.info("correlator.skip", reason="fewer than 2 findings")
            return 0.0

        logger.info("correlator.start", findings=len(real_findings))

        result, cost = await self._router.correlate(state)

        # Mark false positives
        fp_ids = set(result.get("false_positive_ids", []))
        for finding in state.findings:
            if finding.id in fp_ids:
                finding.false_positive = True
                logger.info("correlator.fp_flagged", finding_id=finding.id, title=finding.title)

        # Add attack chains
        for chain_data in result.get("attack_chains", []):
            try:
                combined_sev_str = chain_data.get("combined_severity", "high").lower()
                try:
                    combined_sev = Severity(combined_sev_str)
                except ValueError:
                    combined_sev = Severity.HIGH

                chain = AttackChain(
                    title=chain_data["title"],
                    finding_ids=chain_data.get("finding_ids", []),
                    combined_severity=combined_sev,
                    description=chain_data.get("description", ""),
                    poc=chain_data.get("poc"),
                )
                state.attack_chains.append(chain)
            except (KeyError, TypeError) as e:
                logger.warning("correlator.chain_parse_error", error=str(e))

        logger.info(
            "correlator.done",
            chains=len(state.attack_chains),
            false_positives=len(fp_ids),
        )
        return cost
