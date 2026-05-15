from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from recon_agent.tools.base import Tool

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool
        logger.debug("registry.tool_registered", name=tool.name, category=tool.category)

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not registered. Available: {list(self._tools)}")
        return self._tools[name]

    def all_tools(self) -> list[Tool]:
        return list(self._tools.values())

    def names(self) -> list[str]:
        return list(self._tools.keys())

    def __contains__(self, name: str) -> bool:
        return name in self._tools


def build_default_registry() -> ToolRegistry:
    from recon_agent.tools.recon.subfinder import SubfinderTool
    from recon_agent.tools.recon.httpx_tool import HttpxTool
    from recon_agent.tools.web.nuclei import NucleiTool

    registry = ToolRegistry()
    registry.register(SubfinderTool())
    registry.register(HttpxTool())
    registry.register(NucleiTool())
    return registry
