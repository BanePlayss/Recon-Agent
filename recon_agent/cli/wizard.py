from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

console = Console()


@dataclass
class WizardResult:
    program_url: str
    targets_in_scope: list[str]
    targets_out_of_scope: list[str]
    depth_mode: str
    agent_mode: str
    max_iterations: int
    max_hours: float
    max_cost_usd: float
    gemini_api_key: str


_DEPTH_CHOICES = {
    "Hunt (~45min, secrets + takeovers + critical CVEs) [RECOMENDADO para bug bounty]": "hunt",
    "Rápido (~15min, recon + nuclei safe)": "fast",
    "Padrão (~45min, recon + web scan completo)": "standard",
    "Profundo (~3h, tudo + fuzzing pesado)": "deep",
}

_AGENT_CHOICES = {
    "Adaptativo (LLM decide, aprova ações ativas)": "adaptive",
    "Conservador (sem ações ativas nunca)": "conservative",
}


def run_wizard() -> WizardResult:
    try:
        import questionary
    except ImportError:
        raise ImportError("questionary is not installed. Run: pip install questionary")

    console.print(Panel.fit(
        "[bold cyan]recon-agent v0.1.0[/bold cyan]\nautonomous pentest agent",
        title="",
    ))
    console.print()

    program_url = questionary.text(
        "URL do programa:",
        default="https://hackerone.com/",
    ).ask()
    if not program_url:
        raise SystemExit("Aborted.")

    in_scope_raw = questionary.text(
        "Domínios in-scope (separados por vírgula):",
        instruction="ex: example.com, api.example.com, *.example.com",
    ).ask()
    if not in_scope_raw:
        raise SystemExit("Aborted.")

    out_scope_raw = questionary.text(
        "Domínios out-of-scope (opcional):",
        default="",
    ).ask() or ""

    depth_label = questionary.select(
        "Profundidade:",
        choices=list(_DEPTH_CHOICES.keys()),
    ).ask()
    if not depth_label:
        raise SystemExit("Aborted.")
    depth_mode = _DEPTH_CHOICES[depth_label]

    agent_label = questionary.select(
        "Modo:",
        choices=list(_AGENT_CHOICES.keys()),
    ).ask()
    if not agent_label:
        raise SystemExit("Aborted.")
    agent_mode = _AGENT_CHOICES[agent_label]

    console.print("[dim]Limites (Enter para usar padrão):[/dim]")

    max_iter_raw = questionary.text("Max iterações:", default="100").ask()
    max_hours_raw = questionary.text("Max tempo (horas):", default="4").ask()
    max_cost_raw = questionary.text("Max custo API ($):", default="10.0").ask()

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if not gemini_key:
        gemini_key = questionary.password("GEMINI_API_KEY:").ask() or ""
        if not gemini_key:
            raise SystemExit("GEMINI_API_KEY is required.")

    from recon_agent.core.scope import parse_scope_list

    return WizardResult(
        program_url=program_url.strip(),
        targets_in_scope=parse_scope_list(in_scope_raw),
        targets_out_of_scope=parse_scope_list(out_scope_raw),
        depth_mode=depth_mode,
        agent_mode=agent_mode,
        max_iterations=int(max_iter_raw or 100),
        max_hours=float(max_hours_raw or 4),
        max_cost_usd=float(max_cost_raw or 10.0),
        gemini_api_key=gemini_key,
    )
