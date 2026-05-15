from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

import structlog

from recon_agent.core.state import AgentState, Finding

logger = structlog.get_logger(__name__)

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class Database:
    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> None:
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        schema = _SCHEMA_PATH.read_text(encoding="utf-8")
        self._conn.executescript(schema)
        self._conn.commit()
        logger.debug("db.connected", path=str(self._db_path))

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _cursor(self) -> sqlite3.Cursor:
        if not self._conn:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._conn.cursor()

    def create_run(self, program_url: str, run_dir: Path) -> str:
        run_id = str(uuid.uuid4())
        cur = self._cursor()
        cur.execute(
            "INSERT INTO runs (id, program_url, started_at, status, run_dir) VALUES (?, ?, ?, ?, ?)",
            (run_id, program_url, time.time(), "running", str(run_dir)),
        )
        assert self._conn
        self._conn.commit()
        return run_id

    def finish_run(self, run_id: str, state: AgentState) -> None:
        cur = self._cursor()
        cur.execute(
            "UPDATE runs SET ended_at=?, status=?, cost_usd=?, iterations=? WHERE id=?",
            (time.time(), "done", state.cost_usd, state.iteration, run_id),
        )
        assert self._conn
        self._conn.commit()

    def save_finding(self, run_id: str, finding: Finding) -> None:
        cur = self._cursor()
        cur.execute(
            """INSERT OR REPLACE INTO findings
               (id, run_id, title, severity, asset, description, evidence, poc,
                impact, remediation, cwe, cvss, source_tool, confidence, false_positive, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                finding.id,
                run_id,
                finding.title,
                finding.severity.value,
                finding.asset,
                finding.description,
                finding.evidence,
                finding.poc,
                finding.impact,
                finding.remediation,
                finding.cwe,
                finding.cvss,
                finding.source_tool,
                finding.confidence,
                int(finding.false_positive),
                time.time(),
            ),
        )
        assert self._conn
        self._conn.commit()

    def save_action(
        self, run_id: str, tool: str, target: str, status: str, duration_s: float, iteration: int
    ) -> None:
        cur = self._cursor()
        cur.execute(
            "INSERT INTO actions (run_id, tool, target, status, duration_s, iteration, executed_at) VALUES (?,?,?,?,?,?,?)",
            (run_id, tool, target, status, duration_s, iteration, time.time()),
        )
        assert self._conn
        self._conn.commit()

    def list_runs(self) -> list[dict[str, Any]]:
        cur = self._cursor()
        cur.execute("SELECT * FROM runs ORDER BY started_at DESC")
        return [dict(row) for row in cur.fetchall()]

    def get_findings(self, run_id: str) -> list[dict[str, Any]]:
        cur = self._cursor()
        cur.execute("SELECT * FROM findings WHERE run_id=? ORDER BY severity", (run_id,))
        return [dict(row) for row in cur.fetchall()]
