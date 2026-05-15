from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_PROMPTS_DIR = Path(__file__).parent.parent.parent / "config" / "prompts"


def _get_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_PROMPTS_DIR)),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_planner(context: dict[str, Any]) -> str:
    env = _get_env()
    template = env.get_template("planner.j2")
    return template.render(**context)


def render_observer(context: dict[str, Any]) -> str:
    env = _get_env()
    template = env.get_template("observer.j2")
    return template.render(**context)


def render_reporter(context: dict[str, Any]) -> str:
    env = _get_env()
    template = env.get_template("reporter.j2")
    return template.render(**context)
