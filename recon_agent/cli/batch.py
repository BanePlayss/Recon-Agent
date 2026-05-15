from __future__ import annotations

"""
Batch runner — scans a list of programs sequentially.

Programs file format (one program per line):
    # comments are ignored
    https://hackerone.com/acme  acme.com,*.acme.com  out:legacy.acme.com
    https://hackerone.com/beta  beta.com,api.beta.com

Fields (space-separated):
    1. program_url     HackerOne or Bugcrowd program URL
    2. in_scope        comma-separated domains/wildcards
    3. out_of_scope    (optional) comma-separated, prefixed with "out:"
"""

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

logger = structlog.get_logger(__name__)
console = Console()


@dataclass
class BatchProgram:
    program_url: str
    in_scope: list[str]
    out_of_scope: list[str]


def parse_programs_file(path: Path) -> list[BatchProgram]:
    programs: list[BatchProgram] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            logger.warning("batch.skip_line", reason="missing_scope", line=line[:80])
            continue
        program_url = parts[0]
        in_scope_raw = parts[1]
        out_scope_raw = ""
        for part in parts[2:]:
            if part.startswith("out:"):
                out_scope_raw = part[4:]

        from recon_agent.core.scope import parse_scope_list
        programs.append(BatchProgram(
            program_url=program_url,
            in_scope=parse_scope_list(in_scope_raw),
            out_of_scope=parse_scope_list(out_scope_raw),
        ))
    return programs


async def run_single(
    program: BatchProgram,
    depth_mode: str,
    agent_mode: str,
    max_iterations: int,
    max_hours: float,
    max_cost_usd: float,
    gemini_api_key: str,
    run_base_dir: Path,
) -> dict[str, Any]:
    from datetime import datetime, timezone

    from recon_agent.core.audit import AuditLog, configure_logging
    from recon_agent.core.guardrails import Guardrails
    from recon_agent.core.orchestrator import Orchestrator
    from recon_agent.core.policy_engine import PolicyEngine
    from recon_agent.core.state import AgentState
    from recon_agent.llm.gemini import GeminiClient
    from recon_agent.tools.registry import build_default_registry

    os.environ["GEMINI_API_KEY"] = gemini_api_key

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    handle = program.program_url.rstrip("/").split("/")[-1]
    run_dir = run_base_dir / f"{handle}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    configure_logging(log_file=run_dir / "agent.log", level="INFO")

    state = AgentState(
        program_url=program.program_url,
        targets_in_scope=program.in_scope,
        targets_out_of_scope=program.out_of_scope,
    )

    registry = build_default_registry()
    llm_client = GeminiClient()

    claude_client = None
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if anthropic_key:
        try:
            from recon_agent.llm.claude import ClaudeClient
            claude_client = ClaudeClient(api_key=anthropic_key)
        except Exception:
            pass

    policy = PolicyEngine(state, agent_mode=agent_mode)
    guardrails = Guardrails(
        max_iterations=max_iterations,
        max_hours=max_hours,
        max_cost_usd=max_cost_usd,
    )
    audit = AuditLog(run_dir)

    orchestrator = Orchestrator(
        state=state,
        registry=registry,
        llm_client=llm_client,
        policy=policy,
        guardrails=guardrails,
        audit=audit,
        run_dir=run_dir,
        depth_mode=depth_mode,
        agent_mode=agent_mode,
        claude_client=claude_client,
        enable_deep_analysis=depth_mode in ("standard", "deep", "hunt"),
    )

    final_state = await orchestrator.run()
    return {
        "program_url": program.program_url,
        "run_dir": str(run_dir),
        "findings": len(final_state.real_findings()),
        "cost_usd": final_state.cost_usd,
        "iterations": final_state.iteration,
    }


async def run_batch(
    programs: list[BatchProgram],
    depth_mode: str = "hunt",
    agent_mode: str = "adaptive",
    max_iterations: int = 60,
    max_hours: float = 0.75,
    max_cost_usd: float = 5.0,
    gemini_api_key: str = "",
) -> list[dict[str, Any]]:
    from recon_agent.core.platform import temp_dir
    run_base_dir = temp_dir("batch")
    run_base_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    total = len(programs)

    for i, prog in enumerate(programs, 1):
        console.print(Rule(
            f"[bold cyan]Program {i}/{total}: {prog.program_url}[/bold cyan]"
        ))
        try:
            result = await run_single(
                prog,
                depth_mode=depth_mode,
                agent_mode=agent_mode,
                max_iterations=max_iterations,
                max_hours=max_hours,
                max_cost_usd=max_cost_usd,
                gemini_api_key=gemini_api_key,
                run_base_dir=run_base_dir,
            )
            results.append(result)
            console.print(
                f"[green]Done:[/green] {result['findings']} findings, "
                f"${result['cost_usd']:.4f} cost → {result['run_dir']}"
            )
        except Exception as e:
            logger.error("batch.program_error", program=prog.program_url, error=str(e))
            console.print(f"[red]Error scanning {prog.program_url}: {e}[/red]")
            results.append({"program_url": prog.program_url, "error": str(e)})

    return results
