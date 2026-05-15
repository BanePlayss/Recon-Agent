from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import structlog


def configure_logging(log_file: Path | None = None, level: str = "INFO") -> None:
    """Configure structlog for JSON output."""
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.JSONRenderer(),
    ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(__import__("logging"), level, 20)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


class AuditLog:
    def __init__(self, run_dir: Path) -> None:
        self._path = run_dir / "audit.jsonl"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = structlog.get_logger("audit")

    def _write(self, record: dict[str, Any]) -> None:
        record["_hash"] = hashlib.sha256(
            json.dumps(record, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def log_action(
        self,
        tool: str,
        target: str,
        kwargs: dict[str, Any],
        iteration: int,
        approved: bool,
    ) -> None:
        self._write(
            {
                "event": "action_taken",
                "ts": time.time(),
                "tool": tool,
                "target": target,
                "kwargs": kwargs,
                "iteration": iteration,
                "approved": approved,
            }
        )

    def log_finding(self, finding_id: str, title: str, severity: str, asset: str) -> None:
        self._write(
            {
                "event": "finding_recorded",
                "ts": time.time(),
                "finding_id": finding_id,
                "title": title,
                "severity": severity,
                "asset": asset,
            }
        )

    def log_policy_violation(self, reason: str, context: dict[str, Any]) -> None:
        self._write(
            {
                "event": "policy_violation",
                "ts": time.time(),
                "reason": reason,
                **context,
            }
        )

    def log_guardrail(self, reason: str) -> None:
        self._write(
            {
                "event": "guardrail_triggered",
                "ts": time.time(),
                "reason": reason,
            }
        )

    def log_session_start(self, program_url: str, targets: list[str]) -> None:
        self._write(
            {
                "event": "session_start",
                "ts": time.time(),
                "program_url": program_url,
                "targets": targets,
            }
        )

    def log_session_end(self, iterations: int, cost_usd: float, findings: int) -> None:
        self._write(
            {
                "event": "session_end",
                "ts": time.time(),
                "iterations": iterations,
                "cost_usd": cost_usd,
                "findings": findings,
            }
        )
