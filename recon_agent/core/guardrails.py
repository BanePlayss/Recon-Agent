from __future__ import annotations

import structlog

from recon_agent.core.state import AgentState

logger = structlog.get_logger(__name__)


class GuardrailsExceeded(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Guardrails:
    def __init__(
        self,
        max_iterations: int = 100,
        max_hours: float = 4.0,
        max_cost_usd: float = 10.0,
    ) -> None:
        self.max_iterations = max_iterations
        self.max_hours = max_hours
        self.max_cost_usd = max_cost_usd

    def check(self, state: AgentState) -> None:
        """Raise GuardrailsExceeded if any limit is breached."""
        if state.iteration >= self.max_iterations:
            msg = f"Max iterations reached: {state.iteration}/{self.max_iterations}"
            logger.warning("guardrails.iterations_exceeded", **{"iter": state.iteration})
            raise GuardrailsExceeded(msg)

        elapsed_hours = state.elapsed_s / 3600
        if elapsed_hours >= self.max_hours:
            msg = f"Max time reached: {elapsed_hours:.2f}h/{self.max_hours}h"
            logger.warning("guardrails.time_exceeded", elapsed_h=elapsed_hours)
            raise GuardrailsExceeded(msg)

        if state.cost_usd >= self.max_cost_usd:
            msg = f"Max cost reached: ${state.cost_usd:.4f}/${self.max_cost_usd}"
            logger.warning("guardrails.cost_exceeded", cost_usd=state.cost_usd)
            raise GuardrailsExceeded(msg)

        logger.debug(
            "guardrails.ok",
            iteration=state.iteration,
            elapsed_h=f"{elapsed_hours:.2f}",
            cost_usd=f"{state.cost_usd:.4f}",
        )
