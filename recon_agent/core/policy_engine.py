from __future__ import annotations

import structlog

from recon_agent.core.scope import is_in_scope
from recon_agent.core.state import AgentState, ToolCategory

logger = structlog.get_logger(__name__)


class PolicyViolation(Exception):
    pass


class PolicyEngine:
    def __init__(
        self,
        state: AgentState,
        agent_mode: str = "adaptive",
        blocked_categories: list[ToolCategory] | None = None,
    ) -> None:
        self._state = state
        self._agent_mode = agent_mode
        self._blocked_categories: set[ToolCategory] = set(blocked_categories or [])

        if agent_mode == "conservative":
            self._blocked_categories.update(
                [ToolCategory.EXPLOIT, ToolCategory.RECON_ACTIVE, ToolCategory.INFRA_SCAN]
            )

    def check_target(self, target: str) -> None:
        """Raise PolicyViolation if target is out of scope."""
        if not is_in_scope(
            target,
            self._state.targets_in_scope,
            self._state.targets_out_of_scope,
        ):
            logger.warning("policy.target_out_of_scope", target=target)
            raise PolicyViolation(
                f"Target '{target}' is not in scope. "
                f"In-scope: {self._state.targets_in_scope}"
            )

    def check_category(self, category: ToolCategory) -> None:
        """Raise PolicyViolation if tool category is blocked for this mode."""
        if category in self._blocked_categories:
            logger.warning("policy.category_blocked", category=category)
            raise PolicyViolation(
                f"Tool category '{category}' is blocked in '{self._agent_mode}' mode"
            )

    def check_tool(self, tool_name: str, category: ToolCategory, target: str) -> None:
        """Full policy check: category + target scope."""
        self.check_category(category)
        self.check_target(target)
        logger.debug(
            "policy.check_passed",
            tool=tool_name,
            category=category,
            target=target,
        )

    def requires_approval(self, category: ToolCategory) -> bool:
        """Return True if this category requires manual approval."""
        active_categories = {ToolCategory.EXPLOIT, ToolCategory.RECON_ACTIVE}
        if self._agent_mode == "conservative":
            return False
        return category in active_categories
