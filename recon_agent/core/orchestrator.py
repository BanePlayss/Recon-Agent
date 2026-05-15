from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import structlog
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from recon_agent.core.audit import AuditLog
from recon_agent.core.guardrails import Guardrails, GuardrailsExceeded
from recon_agent.core.policy_engine import PolicyEngine, PolicyViolation
from recon_agent.core.state import ActionLog, AgentState
from recon_agent.llm.gemini import GeminiClient
from recon_agent.llm.router import LLMRouter
from recon_agent.reporting.exporter import Exporter
from recon_agent.reporting.markdown import MarkdownReporter
from recon_agent.tools.registry import ToolRegistry

logger = structlog.get_logger(__name__)
console = Console()


class Orchestrator:
    def __init__(
        self,
        state: AgentState,
        registry: ToolRegistry,
        llm_client: GeminiClient,
        policy: PolicyEngine,
        guardrails: Guardrails,
        audit: AuditLog,
        run_dir: Path,
        depth_mode: str = "standard",
        agent_mode: str = "adaptive",
    ) -> None:
        self._state = state
        self._registry = registry
        self._router = LLMRouter(llm_client)
        self._policy = policy
        self._guardrails = guardrails
        self._audit = audit
        self._run_dir = run_dir
        self._depth_mode = depth_mode
        self._agent_mode = agent_mode
        self._start_time = time.monotonic()

    async def run(self) -> AgentState:
        self._audit.log_session_start(
            self._state.program_url, self._state.targets_in_scope
        )

        console.print(Panel.fit(
            f"[bold green]Starting recon agent[/bold green]\n"
            f"Program: {self._state.program_url}\n"
            f"Targets: {', '.join(self._state.targets_in_scope)}\n"
            f"Mode: {self._depth_mode} / {self._agent_mode}",
            title="recon-agent",
        ))

        try:
            await self._agent_loop()
        except GuardrailsExceeded as e:
            console.print(f"[yellow]Guardrails triggered: {e.reason}[/yellow]")
            self._audit.log_guardrail(e.reason)
        except KeyboardInterrupt:
            console.print("[yellow]Interrupted by user.[/yellow]")
        finally:
            await self._finalize()

        return self._state

    async def _agent_loop(self) -> None:
        available_tools = self._registry.all_tools()

        while True:
            self._state.elapsed_s = time.monotonic() - self._start_time
            self._guardrails.check(self._state)

            console.rule(f"[cyan]Iteration {self._state.iteration + 1}[/cyan]")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Planning next action...", total=None)

                try:
                    action, plan_cost = await self._router.plan(
                        state=self._state,
                        available_tools=available_tools,
                        depth_mode=self._depth_mode,
                        agent_mode=self._agent_mode,
                        max_iterations=self._guardrails.max_iterations,
                        max_hours=self._guardrails.max_hours,
                        max_cost_usd=self._guardrails.max_cost_usd,
                    )
                    self._state.cost_usd += plan_cost
                except Exception as e:
                    logger.error("orchestrator.plan_error", error=str(e))
                    console.print(f"[red]Planner error: {e}[/red]")
                    break

            if action.stop:
                console.print(f"[green]Agent decided to stop: {action.reasoning}[/green]")
                break

            console.print(
                f"[bold]Plan:[/bold] {action.reasoning}\n"
                f"[bold]Action:[/bold] {action.action} → {action.target}"
            )

            if not action.action or action.action not in self._registry:
                logger.warning("orchestrator.unknown_tool", tool=action.action)
                console.print(f"[red]Unknown tool: {action.action!r}[/red]")
                self._state.iteration += 1
                continue

            tool = self._registry.get(action.action)

            # Policy check
            try:
                self._policy.check_tool(action.action, tool.category, action.target)
            except PolicyViolation as e:
                console.print(f"[red]Policy violation: {e}[/red]")
                self._audit.log_policy_violation(str(e), {"tool": action.action, "target": action.target})
                self._state.iteration += 1
                continue

            # Skip duplicate actions
            if self._state.has_action_been_taken(action.action, action.target):
                console.print(
                    f"[yellow]Skipping duplicate: {action.action} on {action.target}[/yellow]"
                )
                self._state.iteration += 1
                continue

            # Manual approval for active tools
            if self._policy.requires_approval(tool.category):
                approved = self._prompt_approval(action.action, action.target, action.reasoning)
                if not approved:
                    console.print("[yellow]Action rejected by user.[/yellow]")
                    self._state.iteration += 1
                    continue
            else:
                approved = True

            self._audit.log_action(
                action.action, action.target, action.kwargs, self._state.iteration, approved
            )

            # Execute tool
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    f"Running {action.action} on {action.target[:60]}...", total=None
                )
                tool_result = await tool.run(action.target, **action.kwargs)

            status_color = "green" if tool_result.status == "success" else "red"
            console.print(
                f"[{status_color}]{action.action} finished:[/] "
                f"status={tool_result.status}, "
                f"duration={tool_result.duration_s:.1f}s"
            )

            self._state.actions_taken.append(
                ActionLog(
                    tool=action.action,
                    target=action.target,
                    status=tool_result.status,
                    duration_s=tool_result.duration_s,
                    iteration=self._state.iteration,
                    kwargs=action.kwargs,
                )
            )

            # Observe
            if tool_result.status in ("success", "error"):
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    progress.add_task("Analyzing results...", total=None)
                    try:
                        observation, obs_cost = await self._router.observe(
                            tool_result, self._state
                        )
                        self._state.cost_usd += obs_cost
                    except Exception as e:
                        logger.error("orchestrator.observe_error", error=str(e))
                        console.print(f"[red]Observer error: {e}[/red]")
                        self._state.iteration += 1
                        continue

                self._apply_observation(observation, action.action)

            self._state.iteration += 1
            self._state.elapsed_s = time.monotonic() - self._start_time
            self._print_status()

    def _apply_observation(self, observation: dict[str, Any], source_tool: str) -> None:
        new_subs = observation.get("new_subdomains", [])
        added = self._state.add_subdomains(new_subs)
        if added > 0:
            console.print(f"[green]+{added} new subdomains[/green]")

        for host, meta in observation.get("alive_hosts_update", {}).items():
            self._state.alive_hosts[host] = meta

        for host, ports in observation.get("open_ports_update", {}).items():
            self._state.open_ports[host] = ports

        findings = self._router.parse_findings(observation, source_tool)
        for f in findings:
            self._state.add_finding(f)
            self._audit.log_finding(f.id, f.title, f.severity.value, f.asset)
            console.print(
                f"[bold red]FINDING [{f.severity.upper()}]:[/] {f.title} @ {f.asset}"
            )

    def _prompt_approval(self, tool: str, target: str, reasoning: str) -> bool:
        console.print(Panel(
            f"[yellow]Manual approval required[/yellow]\n"
            f"Tool: {tool}\n"
            f"Target: {target}\n"
            f"Reasoning: {reasoning}",
            title="Action Requires Approval",
        ))
        answer = input("Approve? [y/N] ").strip().lower()
        return answer in ("y", "yes")

    def _print_status(self) -> None:
        table = Table(title="Current Status", show_header=True)
        table.add_column("Metric")
        table.add_column("Value")
        table.add_row("Iteration", str(self._state.iteration))
        table.add_row("Subdomains", str(len(self._state.discovered_subdomains)))
        table.add_row("Alive hosts", str(len(self._state.alive_hosts)))
        table.add_row("Findings", str(len(self._state.findings)))
        table.add_row("Cost", f"${self._state.cost_usd:.4f}")
        table.add_row(
            "Elapsed",
            f"{self._state.elapsed_s / 60:.1f}min",
        )
        console.print(table)

    async def _finalize(self) -> None:
        self._state.elapsed_s = time.monotonic() - self._start_time
        self._audit.log_session_end(
            self._state.iteration,
            self._state.cost_usd,
            len(self._state.findings),
        )

        reporter = MarkdownReporter()
        exporter = Exporter(self._run_dir)

        report_md = reporter.render(self._state)
        paths = exporter.export(self._state, report_md)

        console.print(Panel(
            f"[bold green]Run complete![/bold green]\n"
            f"Findings: {len(self._state.findings)}\n"
            f"Cost: ${self._state.cost_usd:.4f}\n"
            f"Report: {paths['report']}",
            title="Done",
        ))
