from __future__ import annotations

"""
Hunt scheduler — runs automatically every N hours.

Cycle:
  1. Fetch top H1 programs + detect new/scope-changed ones
  2. Build priority queue (NEW > SCOPE_CHANGE > ROI)
  3. Scan the top-K programs with hunt mode
  4. Deduplicate findings against already-notified ones
  5. Send Telegram alerts for new critical/high findings
  6. Update scan state in DB
  7. Sleep until next cycle
"""

import asyncio
import os
import signal
import time
from pathlib import Path
from typing import Any

import structlog
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

logger = structlog.get_logger(__name__)
console = Console()

_PID_FILE = Path.home() / ".recon-agent" / "scheduler.pid"
_DB_PATH = Path.home() / ".recon-agent" / "recon.db"


class HuntScheduler:
    def __init__(
        self,
        interval_hours: float = 6.0,
        programs_per_cycle: int = 5,
        depth_mode: str = "hunt",
        agent_mode: str = "adaptive",
        max_cost_per_program: float = 5.0,
        max_hours_per_program: float = 0.75,
        notify_severities: set[str] | None = None,
    ) -> None:
        self.interval_hours = interval_hours
        self.programs_per_cycle = programs_per_cycle
        self.depth_mode = depth_mode
        self.agent_mode = agent_mode
        self.max_cost_per_program = max_cost_per_program
        self.max_hours_per_program = max_hours_per_program
        self.notify_severities = notify_severities or {"critical", "high"}
        self._stop_event = asyncio.Event()
        self._cycle_count = 0

    async def run_forever(self) -> None:
        _write_pid()
        console.print(Panel.fit(
            f"[bold green]Hunt Scheduler started[/bold green]\n"
            f"Interval: every {self.interval_hours:.1f}h\n"
            f"Programs/cycle: {self.programs_per_cycle}\n"
            f"Notify: {', '.join(sorted(self.notify_severities))}\n"
            f"Telegram: {'✓' if _telegram_configured() else '✗ (set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)'}",
            title="recon-agent scheduler",
        ))

        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, self._handle_stop)
        loop.add_signal_handler(signal.SIGINT, self._handle_stop)

        try:
            while not self._stop_event.is_set():
                self._cycle_count += 1
                console.rule(f"[cyan]Cycle {self._cycle_count} — {_now_str()}[/cyan]")
                await self._run_cycle()

                if self._stop_event.is_set():
                    break

                next_run = time.time() + self.interval_hours * 3600
                console.print(
                    f"[dim]Next cycle in {self.interval_hours:.1f}h "
                    f"({_ts_str(next_run)})[/dim]"
                )
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=self.interval_hours * 3600,
                    )
                except asyncio.TimeoutError:
                    pass
        finally:
            _remove_pid()
            console.print("[yellow]Scheduler stopped.[/yellow]")

    def _handle_stop(self) -> None:
        console.print("[yellow]Stop signal received...[/yellow]")
        self._stop_event.set()

    async def _run_cycle(self) -> None:
        from recon_agent.storage.db import Database
        from recon_agent.h1.monitor import build_scan_queue
        from recon_agent.cli.batch import run_single, BatchProgram
        from recon_agent.notifications.telegram import (
            send_finding_alert,
            send_summary,
            send_new_program_alert,
        )
        from recon_agent.h1.monitor import finding_hash

        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        if not gemini_key:
            logger.error("scheduler.no_gemini_key")
            console.print("[red]GEMINI_API_KEY not set — skipping cycle[/red]")
            return

        db = Database(_DB_PATH)
        db.connect()

        try:
            # Build scan queue
            queue = await build_scan_queue(
                db,
                min_interval_hours=self.interval_hours,
                max_programs=self.programs_per_cycle,
            )

            if not queue:
                console.print("[dim]No programs due for scanning this cycle.[/dim]")
                return

            _print_queue(queue)

            # Notify about newly discovered programs
            for prog in queue:
                if prog.is_new:
                    await send_new_program_alert(
                        prog.handle, prog.program_url, prog.roi_score
                    )

            # Scan each program
            cycle_stats: list[dict[str, Any]] = []
            for prog in queue:
                if self._stop_event.is_set():
                    break

                console.print(Rule(
                    f"[bold]Scanning {prog.handle}[/bold] "
                    f"[dim](priority={prog.priority.name})[/dim]"
                ))

                run_base = Path("/tmp/recon-agent/scheduler")
                run_base.mkdir(parents=True, exist_ok=True)

                scan_start = time.monotonic()
                try:
                    from recon_agent.cli.batch import BatchProgram as BP
                    result = await run_single(
                        BP(
                            program_url=prog.program_url,
                            in_scope=prog.in_scope,
                            out_of_scope=prog.out_of_scope,
                        ),
                        depth_mode=self.depth_mode,
                        agent_mode=self.agent_mode,
                        max_iterations=60,
                        max_hours=self.max_hours_per_program,
                        max_cost_usd=self.max_cost_per_program,
                        gemini_api_key=gemini_key,
                        run_base_dir=run_base,
                    )
                except Exception as e:
                    logger.error("scheduler.scan_error", handle=prog.handle, error=str(e))
                    console.print(f"[red]Scan error for {prog.handle}: {e}[/red]")
                    db.mark_program_scanned(prog.handle)
                    continue

                elapsed = time.monotonic() - scan_start
                db.mark_program_scanned(prog.handle)

                # Load findings from the run and filter new ones
                new_finding_count = await self._process_findings(
                    db, prog.handle, result, send_finding_alert
                )

                await send_summary(
                    prog.handle,
                    new_findings=new_finding_count,
                    total_cost_usd=result.get("cost_usd", 0.0),
                    elapsed_min=elapsed / 60,
                )

                cycle_stats.append({
                    "handle": prog.handle,
                    "new_findings": new_finding_count,
                    "cost": result.get("cost_usd", 0.0),
                })

            _print_cycle_summary(cycle_stats)

        finally:
            db.close()

    async def _process_findings(
        self,
        db: Any,
        program_handle: str,
        scan_result: dict[str, Any],
        send_fn: Any,
    ) -> int:
        from recon_agent.h1.monitor import finding_hash as fhash

        # Load actual findings from the run dir
        import json
        run_dir = Path(scan_result.get("run_dir", ""))
        findings_file = run_dir / "findings.json"
        if not findings_file.exists():
            return 0

        try:
            findings = json.loads(findings_file.read_text(encoding="utf-8"))
        except Exception:
            return 0

        new_count = 0
        for f in findings:
            if f.get("false_positive"):
                continue
            severity = f.get("severity", "info")
            if severity not in self.notify_severities:
                continue

            fh = fhash(f.get("title", ""), f.get("asset", ""), program_handle)
            if db.is_finding_notified(fh):
                continue

            await send_fn(
                title=f.get("title", "Finding"),
                severity=severity,
                asset=f.get("asset", ""),
                program_handle=program_handle,
                source_tool=f.get("source_tool", "unknown"),
                confidence=float(f.get("confidence", 0.7)),
            )
            db.mark_finding_notified(
                fh, f.get("title", ""), severity, program_handle
            )
            new_count += 1

        return new_count


def _print_queue(queue: list[Any]) -> None:
    t = Table(title="Scan Queue", show_header=True)
    t.add_column("Handle")
    t.add_column("Priority")
    t.add_column("ROI")
    t.add_column("Flags")
    for p in queue:
        flags = []
        if p.is_new:
            flags.append("[green]NEW[/green]")
        if p.scope_changed:
            flags.append("[yellow]SCOPE↑[/yellow]")
        t.add_row(
            p.handle,
            p.priority.name,
            f"{p.roi_score:.3f}",
            " ".join(flags) or "—",
        )
    console.print(t)


def _print_cycle_summary(stats: list[dict[str, Any]]) -> None:
    if not stats:
        return
    total_findings = sum(s["new_findings"] for s in stats)
    total_cost = sum(s["cost"] for s in stats)
    console.print(Panel(
        f"[bold]Cycle complete[/bold]\n"
        f"Programs scanned: {len(stats)}\n"
        f"New findings: [bold green]{total_findings}[/bold green]\n"
        f"API cost: ${total_cost:.4f}",
        title="Cycle Summary",
    ))


def _telegram_configured() -> bool:
    return bool(
        os.environ.get("TELEGRAM_BOT_TOKEN")
        and os.environ.get("TELEGRAM_CHAT_ID")
    )


def _write_pid() -> None:
    _PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PID_FILE.write_text(str(os.getpid()))


def _remove_pid() -> None:
    _PID_FILE.unlink(missing_ok=True)


def _now_str() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _ts_str(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M UTC")


def read_pid() -> int | None:
    if _PID_FILE.exists():
        try:
            return int(_PID_FILE.read_text().strip())
        except Exception:
            pass
    return None
