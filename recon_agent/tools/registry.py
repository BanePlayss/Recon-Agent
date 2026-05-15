from __future__ import annotations

import structlog

from recon_agent.tools.base import Tool

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

    def available_tools(self) -> list[Tool]:
        """Return only tools whose binary is present in PATH."""
        return [t for t in self._tools.values() if t.is_available()]

    def names(self) -> list[str]:
        return list(self._tools.keys())

    def __contains__(self, name: str) -> bool:
        return name in self._tools


def build_default_registry() -> ToolRegistry:
    from recon_agent.tools.recon.subfinder import SubfinderTool
    from recon_agent.tools.recon.httpx_tool import HttpxTool
    from recon_agent.tools.recon.amass import AmassTool
    from recon_agent.tools.recon.nmap_tool import NmapTool
    from recon_agent.tools.recon.masscan import MasscanTool
    from recon_agent.tools.recon.theharvester import TheHarvesterTool
    from recon_agent.tools.recon.dnsx import DnsxTool
    from recon_agent.tools.recon.crtsh import CrtshTool
    from recon_agent.tools.recon.naabu import NaabuTool
    from recon_agent.tools.web.nuclei import NucleiTool
    from recon_agent.tools.web.ffuf import FfufTool
    from recon_agent.tools.web.katana import KatanaTool
    from recon_agent.tools.web.nikto import NiktoTool
    from recon_agent.tools.web.wpscan import WpscanTool
    from recon_agent.tools.web.wafw00f import Wafw00fTool
    from recon_agent.tools.web.testssl import TestsslTool
    from recon_agent.tools.web.arjun import ArjunTool
    from recon_agent.tools.web.gobuster import GobusterTool
    from recon_agent.tools.exploit.sqlmap import SqlmapTool
    from recon_agent.tools.exploit.dalfox import DalfoxTool
    from recon_agent.tools.exploit.xsstrike import XSStrikeTool
    from recon_agent.tools.exploit.nosqlmap import NoSQLMapTool
    from recon_agent.tools.exploit.commix import CommixTool
    from recon_agent.tools.secrets.trufflehog import TrufflehogTool
    from recon_agent.tools.secrets.gitleaks import GitleaksTool
    from recon_agent.tools.secrets.secretfinder import SecretFinderTool
    from recon_agent.tools.cloud.trivy import TrivyTool
    from recon_agent.tools.cloud.prowler import ProwlerTool
    from recon_agent.tools.recon.takeover import SubdomainTakeoverTool
    from recon_agent.tools.secrets.jssecrets import JsSecretsTool

    registry = ToolRegistry()
    for tool in [
        # recon passive
        SubfinderTool(), AmassTool(), TheHarvesterTool(), CrtshTool(),
        # recon active
        HttpxTool(), DnsxTool(), Wafw00fTool(), SubdomainTakeoverTool(),
        # infra
        NmapTool(), NaabuTool(), MasscanTool(),
        # web scan
        NucleiTool(), FfufTool(), KatanaTool(), NiktoTool(),
        WpscanTool(), TestsslTool(), ArjunTool(), GobusterTool(),
        # exploit (all require manual approval)
        SqlmapTool(), DalfoxTool(), XSStrikeTool(), NoSQLMapTool(), CommixTool(),
        # secrets
        TrufflehogTool(), GitleaksTool(), SecretFinderTool(), JsSecretsTool(),
        # cloud
        TrivyTool(), ProwlerTool(),
    ]:
        registry.register(tool)
    return registry
