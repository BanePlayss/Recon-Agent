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
def hunt(
    top: Annotated[int, typer.Option("--top", "-n", help="Number of top programs to scan")] = 5,
    mode: Annotated[str, typer.Option("--mode", "-m", help="Agent mode: adaptive|conservative")] = "adaptive",
    max_cost: Annotated[float, typer.Option("--max-cost", help="Max API cost per program (USD)")] = 5.0,
    max_hours: Annotated[float, typer.Option("--max-hours", help="Max hours per program")] = 0.75,
) -> None:
    """Auto-select top HackerOne programs by ROI and run hunt mode on each."""
    _load_env()

    async def _run() -> None:
        from recon_agent.h1.program_scanner import top_programs
        from recon_agent.cli.batch import run_batch, BatchProgram

        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        if not gemini_key:
            console.print("[red]GEMINI_API_KEY not set.[/red]")
            raise typer.Exit(1)

        console.print("[cyan]Fetching top HackerOne programs by ROI score...[/cyan]")
        programs = await top_programs(n=top)

        if not programs:
            console.print("[yellow]No programs found.[/yellow]")
            raise typer.Exit()

        table = __import__("rich.table", fromlist=["Table"]).Table(
            title=f"Top {len(programs)} Programs", show_header=True
        )
        table.add_column("Handle")
        table.add_column("Critical $")
        table.add_column("High $")
        table.add_column("Response%")
        table.add_column("ROI Score")
        for p in programs:
            table.add_row(
                p.handle,
                f"${p.min_bounty_critical:,}",
                f"${p.min_bounty_high:,}",
                f"{p.response_efficiency_pct:.0f}%",
                f"{p.roi_score:.3f}",
            )
        console.print(table)

        batch_programs = [
            BatchProgram(
                program_url=p.program_url,
                in_scope=p.in_scope or [p.handle + ".com"],
                out_of_scope=p.out_of_scope,
            )
            for p in programs
        ]

        results = await run_batch(
            batch_programs,
            depth_mode="hunt",
            agent_mode=mode,
            max_cost_usd=max_cost,
            max_hours=max_hours,
            gemini_api_key=gemini_key,
        )

        total_findings = sum(r.get("findings", 0) for r in results)
        total_cost = sum(r.get("cost_usd", 0.0) for r in results)
        console.print(f"\n[bold green]Hunt complete:[/bold green] "
                      f"{total_findings} findings across {len(results)} programs, "
                      f"${total_cost:.4f} total API cost")

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(0)


@app.command()
def batch(
    programs_file: Annotated[str, typer.Argument(help="Path to programs file")],
    depth: Annotated[str, typer.Option("--depth", "-d", help="Depth mode: hunt|fast|standard|deep")] = "hunt",
    mode: Annotated[str, typer.Option("--mode", "-m", help="Agent mode: adaptive|conservative")] = "adaptive",
    max_cost: Annotated[float, typer.Option("--max-cost", help="Max API cost per program (USD)")] = 5.0,
    max_hours: Annotated[float, typer.Option("--max-hours", help="Max hours per program")] = 0.75,
) -> None:
    """Run hunt mode on a list of programs from a file.

    File format (one program per line):
      https://hackerone.com/acme  acme.com,*.acme.com  out:legacy.acme.com
    """
    _load_env()

    path = Path(programs_file)
    if not path.exists():
        console.print(f"[red]File not found: {programs_file}[/red]")
        raise typer.Exit(1)

    async def _run() -> None:
        from recon_agent.cli.batch import run_batch, parse_programs_file

        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        if not gemini_key:
            console.print("[red]GEMINI_API_KEY not set.[/red]")
            raise typer.Exit(1)

        programs = parse_programs_file(path)
        if not programs:
            console.print("[yellow]No programs found in file.[/yellow]")
            raise typer.Exit()

        console.print(f"[cyan]Loaded {len(programs)} programs from {programs_file}[/cyan]")
        results = await run_batch(
            programs,
            depth_mode=depth,
            agent_mode=mode,
            max_cost_usd=max_cost,
            max_hours=max_hours,
            gemini_api_key=gemini_key,
        )
        total_findings = sum(r.get("findings", 0) for r in results)
        total_cost = sum(r.get("cost_usd", 0.0) for r in results)
        console.print(f"\n[bold green]Batch complete:[/bold green] "
                      f"{total_findings} findings, ${total_cost:.4f} total cost")

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(0)


@app.command()
def programs(
    top: Annotated[int, typer.Option("--top", "-n", help="Number of programs to show")] = 10,
) -> None:
    """List top HackerOne programs ranked by automated hunting ROI score."""
    _load_env()

    async def _run() -> None:
        from recon_agent.h1.program_scanner import top_programs
        results = await top_programs(n=top)
        table = __import__("rich.table", fromlist=["Table"]).Table(
            title="Top Programs by ROI Score", show_header=True
        )
        table.add_column("Rank")
        table.add_column("Handle")
        table.add_column("Name")
        table.add_column("Critical $")
        table.add_column("High $")
        table.add_column("Response%")
        table.add_column("ROI Score")
        table.add_column("~Weekly $")
        for rank, p in enumerate(results, 1):
            table.add_row(
                str(rank),
                p.handle,
                p.name[:30],
                f"${p.min_bounty_critical:,}",
                f"${p.min_bounty_high:,}",
                f"{p.response_efficiency_pct:.0f}%",
                f"{p.roi_score:.3f}",
                f"${p.weekly_expected_usd:,.0f}",
            )
        console.print(table)
        if not os.environ.get("H1_USERNAME"):
            console.print(
                "[dim]Tip: Set H1_USERNAME + H1_API_TOKEN in ~/.recon-agent/.env "
                "to fetch live program data from the H1 API.[/dim]"
            )

    asyncio.run(_run())


@app.command()
def findings(
    run_id: Annotated[str, typer.Option("--run", "-r", help="Filter by run ID prefix")] = "",
    severity: Annotated[str, typer.Option("--severity", "-s", help="Filter: critical,high,medium,low,info")] = "",
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max findings to show")] = 50,
) -> None:
    """List all confirmed findings across runs. Use with 'draft' to generate reports."""
    _load_env()
    db_path = Path.home() / ".recon-agent" / "recon.db"
    if not db_path.exists():
        console.print("[yellow]No database found. Run a scan first.[/yellow]")
        raise typer.Exit()

    from recon_agent.storage.db import Database
    db = Database(db_path)
    db.connect()
    runs = db.list_runs()
    db.close()

    if run_id:
        runs = [r for r in runs if r["id"].startswith(run_id)]

    severity_filter = {s.strip().lower() for s in severity.split(",") if s.strip()}

    all_findings: list[dict] = []
    db.connect()
    for run in runs:
        for f in db.get_findings(run["id"]):
            if f.get("false_positive"):
                continue
            if severity_filter and f["severity"] not in severity_filter:
                continue
            f["program_url"] = run["program_url"]
            f["run_id_short"] = run["id"][:8]
            all_findings.append(f)
    db.close()

    all_findings.sort(key=lambda f: (
        ["critical", "high", "medium", "low", "info"].index(f.get("severity", "info")),
    ))

    _SEV_COLOR = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    t = Table(title=f"Findings ({min(len(all_findings), limit)} shown)", show_header=True)
    t.add_column("ID", style="dim", max_width=10)
    t.add_column("Severity", max_width=9)
    t.add_column("Title", max_width=50)
    t.add_column("Asset", max_width=40)
    t.add_column("Conf%", max_width=5)
    t.add_column("Program", max_width=25)

    for f in all_findings[:limit]:
        sev = f.get("severity", "info")
        color = _SEV_COLOR.get(sev, "white")
        t.add_row(
            f["id"][:8],
            f"[{color}]{sev.upper()}[/{color}]",
            f.get("title", "")[:50],
            f.get("asset", "")[:40],
            f"{float(f.get('confidence', 0)) * 100:.0f}",
            f.get("program_url", "")[:25],
        )

    console.print(t)
    if len(all_findings) > limit:
        console.print(f"[dim]... and {len(all_findings) - limit} more. Use --limit to show more.[/dim]")
    console.print("[dim]Use: recon-agent draft <finding-id-prefix> to generate a report[/dim]")


@app.command()
def draft(
    finding_id: Annotated[str, typer.Argument(help="Finding ID or prefix (from 'recon-agent findings')")],
    output: Annotated[str, typer.Option("--output", "-o", help="Save to file path")] = "",
    edit: Annotated[bool, typer.Option("--edit", "-e", help="Open in $EDITOR after generating")] = False,
) -> None:
    """Generate a ready-to-submit HackerOne report from a finding.

    Example:
      recon-agent draft abc12345
      recon-agent draft abc12345 --output ~/reports/xss-shopify.md --edit
    """
    _load_env()
    db_path = Path.home() / ".recon-agent" / "recon.db"
    if not db_path.exists():
        console.print("[red]No database found.[/red]")
        raise typer.Exit(1)

    from recon_agent.storage.db import Database
    from recon_agent.core.state import Finding, Severity
    from recon_agent.reporting.drafter import draft as make_draft

    db = Database(db_path)
    db.connect()
    runs = db.list_runs()

    matched_finding: dict | None = None
    matched_program = ""
    for run in runs:
        for f in db.get_findings(run["id"]):
            if f["id"].startswith(finding_id):
                matched_finding = f
                matched_program = run["program_url"]
                break
        if matched_finding:
            break
    db.close()

    if not matched_finding:
        console.print(f"[red]No finding matching '{finding_id}'. Run 'recon-agent findings' to list.[/red]")
        raise typer.Exit(1)

    # Reconstruct Finding from DB dict
    finding = Finding(
        id=matched_finding["id"],
        title=matched_finding["title"],
        severity=Severity(matched_finding["severity"]),
        asset=matched_finding["asset"],
        description=matched_finding.get("description") or "",
        evidence=matched_finding.get("evidence") or "",
        poc=matched_finding.get("poc"),
        impact=matched_finding.get("impact") or "",
        remediation=matched_finding.get("remediation") or "",
        cwe=matched_finding.get("cwe"),
        cvss=matched_finding.get("cvss"),
        source_tool=matched_finding.get("source_tool") or "unknown",
        confidence=float(matched_finding.get("confidence") or 0.7),
    )

    report_md = make_draft(finding, matched_program)

    # Print to terminal
    from rich.markdown import Markdown
    from rich.panel import Panel
    console.print(Panel(
        Markdown(report_md),
        title=f"[bold]Draft report — {finding.severity.upper()}[/bold]",
        subtitle=f"[dim]Finding: {finding.id[:8]}[/dim]",
    ))

    # Save to file
    if output:
        save_path = Path(output)
    else:
        safe_title = "".join(c if c.isalnum() or c in "-_" else "_" for c in finding.title[:40])
        save_path = Path.home() / ".recon-agent" / "drafts" / f"{finding.id[:8]}_{safe_title}.md"

    save_path.parent.mkdir(parents=True, exist_ok=True)
    save_path.write_text(report_md, encoding="utf-8")
    console.print(f"\n[green]Saved:[/green] {save_path}")

    if edit:
        editor = os.environ.get("EDITOR", "nano")
        import subprocess
        subprocess.run([editor, str(save_path)])



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


@app.command()
def scheduler_start(
    interval: Annotated[float, typer.Option("--interval", "-i", help="Hours between cycles")] = 6.0,
    top: Annotated[int, typer.Option("--top", "-n", help="Programs to scan per cycle")] = 5,
    depth: Annotated[str, typer.Option("--depth", "-d", help="Depth mode: hunt|fast|standard")] = "hunt",
    mode: Annotated[str, typer.Option("--mode", "-m", help="Agent mode: adaptive|conservative")] = "adaptive",
    max_cost: Annotated[float, typer.Option("--max-cost", help="Max API cost per program (USD)")] = 5.0,
    max_hours: Annotated[float, typer.Option("--max-hours", help="Max hours per program")] = 0.75,
    severities: Annotated[str, typer.Option("--notify", help="Severities to notify: critical,high,medium")] = "critical,high",
) -> None:
    """Start the hunt scheduler (runs every N hours, sends Telegram alerts).

    Tip: run in background with: nohup recon-agent scheduler-start &
    """
    _load_env()

    notify_set = {s.strip().lower() for s in severities.split(",") if s.strip()}

    from recon_agent.scheduler.scheduler import HuntScheduler
    sched = HuntScheduler(
        interval_hours=interval,
        programs_per_cycle=top,
        depth_mode=depth,
        agent_mode=mode,
        max_cost_per_program=max_cost,
        max_hours_per_program=max_hours,
        notify_severities=notify_set,
    )
    try:
        asyncio.run(sched.run_forever())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scheduler stopped.[/yellow]")


@app.command()
def scheduler_stop() -> None:
    """Stop a running scheduler daemon by PID."""
    _load_env()
    import signal as _sig
    from recon_agent.scheduler.scheduler import read_pid
    pid = read_pid()
    if pid is None:
        console.print("[yellow]No running scheduler found (no PID file).[/yellow]")
        raise typer.Exit()
    try:
        import os as _os
        _os.kill(pid, _sig.SIGTERM)
        console.print(f"[green]Sent SIGTERM to scheduler PID {pid}[/green]")
    except ProcessLookupError:
        console.print(f"[yellow]Process {pid} not found — cleaning up PID file.[/yellow]")
        from pathlib import Path
        (Path.home() / ".recon-agent" / "scheduler.pid").unlink(missing_ok=True)


@app.command()
def scheduler_status() -> None:
    """Show scheduler status: PID, next scan queue, notification config."""
    _load_env()
    from recon_agent.scheduler.scheduler import read_pid, _DB_PATH, _PID_FILE
    from recon_agent.storage.db import Database

    pid = read_pid()
    if pid:
        console.print(f"[green]Scheduler running[/green] (PID {pid})")
    else:
        console.print("[yellow]Scheduler not running[/yellow]")

    has_telegram = bool(
        os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID")
    )
    console.print(f"Telegram alerts: {'[green]configured[/green]' if has_telegram else '[red]not configured[/red]'}")

    if not _DB_PATH.exists():
        console.print("[dim]No scan history yet.[/dim]")
        return

    db = Database(_DB_PATH)
    db.connect()
    programs = db.get_programs_due(0)
    db.close()

    if not programs:
        console.print("[dim]No programs tracked yet.[/dim]")
        return

    t = Table(title="Tracked Programs", show_header=True)
    t.add_column("Handle")
    t.add_column("Last Scanned")
    t.add_column("Scans")
    for p in sorted(programs, key=lambda x: x.get("last_scanned_at") or 0):
        last = p.get("last_scanned_at")
        last_str = (
            datetime.fromtimestamp(last).strftime("%m-%d %H:%M")
            if last else "[dim]never[/dim]"
        )
        t.add_row(p["handle"], last_str, str(p.get("scan_count", 0)))
    console.print(t)


def main() -> None:
    _load_env()
    app()


if __name__ == "__main__":
    main()
