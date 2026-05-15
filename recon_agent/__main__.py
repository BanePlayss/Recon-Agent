from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import structlog
from rich.console import Console

console = Console()


def _load_env() -> None:
    """Load .env from ~/.recon-agent/.env if it exists."""
    env_path = Path.home() / ".recon-agent" / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())


async def _run() -> None:
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
    logger = structlog.get_logger(__name__)

    os.environ["GEMINI_API_KEY"] = wizard_result.gemini_api_key

    state = AgentState(
        program_url=wizard_result.program_url,
        targets_in_scope=wizard_result.targets_in_scope,
        targets_out_of_scope=wizard_result.targets_out_of_scope,
    )

    registry = build_default_registry()
    llm_client = GeminiClient()
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


def main() -> None:
    _load_env()
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
