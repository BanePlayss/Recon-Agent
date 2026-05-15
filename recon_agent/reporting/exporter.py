from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import AgentState

logger = structlog.get_logger(__name__)


class Exporter:
    def __init__(self, run_dir: Path) -> None:
        self._run_dir = run_dir
        run_dir.mkdir(parents=True, exist_ok=True)

    def export(self, state: AgentState, report_md: str) -> dict[str, Path]:
        report_path = self._run_dir / "report.md"
        report_path.write_text(report_md, encoding="utf-8")

        state_path = self._run_dir / "state.json"
        state_data = state.model_dump(mode="json")
        state_path.write_text(
            json.dumps(state_data, indent=2, default=str), encoding="utf-8"
        )

        findings_path = self._run_dir / "findings.json"
        findings_data = [f.model_dump(mode="json") for f in state.findings]
        findings_path.write_text(
            json.dumps(findings_data, indent=2), encoding="utf-8"
        )

        logger.info(
            "exporter.done",
            run_dir=str(self._run_dir),
            report=str(report_path),
            findings=len(state.findings),
        )

        return {
            "report": report_path,
            "state": state_path,
            "findings": findings_path,
        }
