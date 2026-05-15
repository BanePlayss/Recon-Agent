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

    # ── Scheduler methods ────────────────────────────────────────────────────

    def upsert_scheduler_program(
        self,
        handle: str,
        program_url: str,
        scope_hash: str,
    ) -> bool:
        """Insert or update a tracked program. Returns True if it's new."""
        cur = self._cursor()
        cur.execute(
            "SELECT handle, scope_hash FROM scheduler_programs WHERE handle=?",
            (handle,),
        )
        row = cur.fetchone()
        now = time.time()
        if row is None:
            cur.execute(
                """INSERT INTO scheduler_programs
                   (handle, program_url, scope_hash, scan_count, first_seen_at)
                   VALUES (?, ?, ?, 0, ?)""",
                (handle, program_url, scope_hash, now),
            )
            assert self._conn
            self._conn.commit()
            return True  # new program
        if row["scope_hash"] != scope_hash:
            cur.execute(
                "UPDATE scheduler_programs SET scope_hash=?, program_url=? WHERE handle=?",
                (scope_hash, program_url, handle),
            )
            assert self._conn
            self._conn.commit()
        return False  # existing

    def mark_program_scanned(self, handle: str) -> None:
        cur = self._cursor()
        cur.execute(
            """UPDATE scheduler_programs
               SET last_scanned_at=?, scan_count=scan_count+1
               WHERE handle=?""",
            (time.time(), handle),
        )
        assert self._conn
        self._conn.commit()

    def get_programs_due(self, min_interval_hours: float) -> list[dict[str, Any]]:
        """Return programs not scanned in the last min_interval_hours."""
        threshold = time.time() - min_interval_hours * 3600
        cur = self._cursor()
        cur.execute(
            """SELECT * FROM scheduler_programs
               WHERE last_scanned_at IS NULL OR last_scanned_at < ?
               ORDER BY last_scanned_at ASC NULLS FIRST""",
            (threshold,),
        )
        return [dict(row) for row in cur.fetchall()]

    def is_finding_notified(self, finding_hash: str) -> bool:
        cur = self._cursor()
        cur.execute(
            "SELECT 1 FROM notified_findings WHERE finding_hash=?", (finding_hash,)
        )
        return cur.fetchone() is not None

    def mark_finding_notified(
        self, finding_hash: str, title: str, severity: str, program_handle: str
    ) -> None:
        cur = self._cursor()
        cur.execute(
            """INSERT OR IGNORE INTO notified_findings
               (finding_hash, title, severity, program_handle, notified_at)
               VALUES (?, ?, ?, ?, ?)""",
            (finding_hash, title, severity, program_handle, time.time()),
        )
        assert self._conn
        self._conn.commit()
