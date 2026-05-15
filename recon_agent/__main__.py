from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="recon-agent",
    help="Autonomous pentest agent for bug bounty programs.",
    add_completion=False,
    no_args_is_help=False,
)
console = Console()


def _load_env() -> None:
    env_path = Path.home() / ".recon-agent" / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())


async def _run_agent() -> None:
    from recon_agent.cli.wizard import run_wizard
    from recon_agent.core.audit import AuditLog, configure_logging
    from recon_agent.core.guardrails import Guardrails
    from recon_agent.core.orchestrator import Orchestrator
    from recon_agent.core.policy_engine import PolicyEngine
    from recon_agent.core.state import AgentState
    from recon_agent.llm.gemini import GeminiClient
    from recon_agent.storage.db import Database
    from recon_agent.tools.registry import build_default_registry

    wizard_result = run_wizard()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = Path("/tmp/recon-agent/runs") / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    configure_logging(log_file=run_dir / "agent.log", level="INFO")

    os.environ["GEMINI_API_KEY"] = wizard_result.gemini_api_key

    state = AgentState(
        program_url=wizard_result.program_url,
        targets_in_scope=wizard_result.targets_in_scope,
        targets_out_of_scope=wizard_result.targets_out_of_scope,
    )

    registry = build_default_registry()
    available = registry.available_tools()
    console.print(
        f"[dim]{len(available)}/{len(registry.all_tools())} tools available[/dim]"
    )

    llm_client = GeminiClient()

    claude_client = None
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            from recon_agent.llm.claude import ClaudeClient
            claude_client = ClaudeClient(api_key=anthropic_key)
            console.print("[green]Claude API: deep analysis enabled[/green]")
        except Exception as e:
            console.print(f"[yellow]Claude API unavailable ({e})[/yellow]")

    policy = PolicyEngine(state, agent_mode=wizard_result.agent_mode)
    guardrails = Guardrails(
        max_iterations=wizard_result.max_iterations,
        max_hours=wizard_result.max_hours,
        max_cost_usd=wizard_result.max_cost_usd,
    )
    audit = AuditLog(run_dir)

    db_path = Path.home() / ".recon-agent" / "recon.db"
    db = Database(db_path)
    db.connect()
    run_id = db.create_run(wizard_result.program_url, run_dir)

    orchestrator = Orchestrator(
        state=state,
        registry=registry,
        llm_client=llm_client,
        policy=policy,
        guardrails=guardrails,
        audit=audit,
        run_dir=run_dir,
        depth_mode=wizard_result.depth_mode,
        agent_mode=wizard_result.agent_mode,
        claude_client=claude_client,
        enable_deep_analysis=wizard_result.depth_mode in ("standard", "deep"),
    )

    final_state = await orchestrator.run()

    for finding in final_state.findings:
        db.save_finding(run_id, finding)
    for action in final_state.actions_taken:
        db.save_action(
            run_id, action.tool, action.target, action.status,
            action.duration_s, action.iteration
        )
    db.finish_run(run_id, final_state)
    db.close()


@app.callback(invoke_without_command=True)
def default(ctx: typer.Context) -> None:
    """Run the interactive wizard and start a new recon session."""
    if ctx.invoked_subcommand is None:
        _load_env()
        try:
            asyncio.run(_run_agent())
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
            sys.exit(0)


@app.command()
def runs() -> None:
    """List past recon runs from the local database."""
    _load_env()
    from recon_agent.storage.db import Database
    db_path = Path.home() / ".recon-agent" / "recon.db"
    if not db_path.exists():
        console.print("[yellow]No runs found (database does not exist).[/yellow]")
        raise typer.Exit()

    db = Database(db_path)
    db.connect()
    run_list = db.list_runs()
    db.close()

    if not run_list:
        console.print("[yellow]No runs found.[/yellow]")
        return

    table = Table(title="Past Runs", show_header=True)
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Program")
    table.add_column("Status")
    table.add_column("Cost")
    table.add_column("Findings")
    table.add_column("Started")

    for run in run_list:
        run_id_short = run["id"][:8]
        started = datetime.fromtimestamp(run["started_at"]).strftime("%Y-%m-%d %H:%M")
        cost = f"${run.get('cost_usd', 0.0):.4f}"
        findings_count = str(run.get("iterations", "?"))
        table.add_row(
            run_id_short,
            run["program_url"][:50],
            run["status"],
            cost,
            findings_count,
            started,
        )

    console.print(table)


@app.command()
def report(
    run_id: Annotated[str, typer.Argument(help="Run ID (prefix is enough)")],
    fmt: Annotated[str, typer.Option("--format", "-f", help="Output format: md|json|h1")] = "md",
) -> None:
    """Print the report for a past run."""
    _load_env()
    from recon_agent.storage.db import Database
    db_path = Path.home() / ".recon-agent" / "recon.db"
    if not db_path.exists():
        console.print("[red]No database found.[/red]")
        raise typer.Exit(1)

    db = Database(db_path)
    db.connect()
    run_list = db.list_runs()
    db.close()

    matched = [r for r in run_list if r["id"].startswith(run_id)]
    if not matched:
        console.print(f"[red]No run matching '{run_id}' found.[/red]")
        raise typer.Exit(1)

    run = matched[0]
    run_dir = Path(run["run_dir"]) if run.get("run_dir") else None

    if not run_dir or not run_dir.exists():
        console.print(f"[red]Run directory not found: {run_dir}[/red]")
        raise typer.Exit(1)

    if fmt == "md":
        path = run_dir / "report.md"
    elif fmt == "json":
        path = run_dir / "findings.json"
    elif fmt == "h1":
        path = run_dir / "h1_reports.json"
    else:
        console.print(f"[red]Unknown format: {fmt!r}. Use md, json, or h1.[/red]")
        raise typer.Exit(1)

    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise typer.Exit(1)

    content = path.read_text(encoding="utf-8")
    if fmt in ("json", "h1"):
        import json as _json
        console.print_json(_json.dumps(_json.loads(content), indent=2))
    else:
        from rich.markdown import Markdown
        console.print(Markdown(content))


@app.command()
def tools() -> None:
    """List all registered tools and their availability."""
    from recon_agent.tools.registry import build_default_registry
    registry = build_default_registry()

    table = Table(title="Registered Tools", show_header=True)
    table.add_column("Tool")
    table.add_column("Category")
    table.add_column("Approval?")
    table.add_column("Available")

    for tool in sorted(registry.all_tools(), key=lambda t: (t.category, t.name)):
        available = tool.is_available()
        avail_str = "[green]yes[/green]" if available else "[red]no[/red]"
        approval_str = "[yellow]yes[/yellow]" if tool.requires_approval else "no"
        table.add_row(tool.name, tool.category, approval_str, avail_str)

    all_tools = registry.all_tools()
    available_count = sum(1 for t in all_tools if t.is_available())
    console.print(table)
    console.print(f"\n{available_count}/{len(all_tools)} tools available in PATH")


def main() -> None:
    _load_env()
    app()


if __name__ == "__main__":
    main()
