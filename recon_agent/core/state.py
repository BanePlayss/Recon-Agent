from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ToolCategory(str, Enum):
    RECON_PASSIVE = "recon_passive"
    RECON_ACTIVE = "recon_active"
    INFRA_SCAN = "infra_scan"
    WEB_SCAN = "web_scan"
    EXPLOIT = "exploit"
    SECRETS = "secrets"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: Severity
    asset: str
    description: str
    evidence: str
    poc: str | None = None
    impact: str
    remediation: str
    cwe: str | None = None
    cvss: float | None = None
    source_tool: str
    confidence: float = Field(ge=0.0, le=1.0)
    false_positive: bool = False


class ActionLog(BaseModel):
    tool: str
    target: str
    status: str
    duration_s: float
    iteration: int
    kwargs: dict[str, Any] = Field(default_factory=dict)


class AgentState(BaseModel):
    program_url: str
    targets_in_scope: list[str] = Field(default_factory=list)
    targets_out_of_scope: list[str] = Field(default_factory=list)
    discovered_subdomains: set[str] = Field(default_factory=set)
    alive_hosts: dict[str, dict[str, Any]] = Field(default_factory=dict)
    open_ports: dict[str, list[int]] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    actions_taken: list[ActionLog] = Field(default_factory=list)
    iteration: int = 0
    cost_usd: float = 0.0
    elapsed_s: float = 0.0

    model_config = {"arbitrary_types_allowed": True}

    def add_finding(self, finding: Finding) -> None:
        for existing in self.findings:
            if existing.title == finding.title and existing.asset == finding.asset:
                return
        self.findings.append(finding)

    def add_subdomains(self, subdomains: list[str]) -> int:
        before = len(self.discovered_subdomains)
        self.discovered_subdomains.update(subdomains)
        return len(self.discovered_subdomains) - before

    def has_action_been_taken(self, tool: str, target: str) -> bool:
        return any(
            a.tool == tool and a.target == target for a in self.actions_taken
        )
