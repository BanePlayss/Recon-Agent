from __future__ import annotations

"""
H1 program monitor — detects new programs and scope changes, maintains
a persistent scan queue prioritized by: NEW_PROGRAM > SCOPE_CHANGE > ROI_SCORE.
"""

import hashlib
import json
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ScanPriority(int, Enum):
    NEW_PROGRAM = 3
    SCOPE_CHANGE = 2
    REGULAR = 1


@dataclass
class QueuedProgram:
    handle: str
    program_url: str
    in_scope: list[str]
    out_of_scope: list[str]
    priority: ScanPriority
    roi_score: float
    is_new: bool = False
    scope_changed: bool = False

    @property
    def sort_key(self) -> tuple[int, float]:
        return (self.priority.value, self.roi_score)


def _scope_hash(in_scope: list[str]) -> str:
    """Stable hash of a scope list for change detection."""
    return hashlib.sha256(
        json.dumps(sorted(in_scope), separators=(",", ":")).encode()
    ).hexdigest()[:16]


async def build_scan_queue(
    db: Any,
    min_interval_hours: float = 24.0,
    max_programs: int = 10,
) -> list[QueuedProgram]:
    """
    Fetch H1 programs, cross-reference with scan history, and return a
    prioritized queue of programs to scan next.
    """
    from recon_agent.h1.program_scanner import fetch_programs

    programs = await fetch_programs(page_size=50, max_pages=4)
    if not programs:
        logger.warning("monitor.no_programs")
        return []

    queue: list[QueuedProgram] = []

    for prog in programs:
        in_scope = prog.in_scope or [f"*.{prog.handle}.com", f"{prog.handle}.com"]
        scope_hash = _scope_hash(in_scope)

        is_new = db.upsert_scheduler_program(
            handle=prog.handle,
            program_url=prog.program_url,
            scope_hash=scope_hash,
        )

        due_records = db.get_programs_due(min_interval_hours)
        due_handles = {r["handle"] for r in due_records}

        if is_new:
            priority = ScanPriority.NEW_PROGRAM
        elif prog.handle in due_handles:
            scope_changed = _detect_scope_change(db, prog.handle, scope_hash)
            priority = ScanPriority.SCOPE_CHANGE if scope_changed else ScanPriority.REGULAR
        else:
            continue  # scanned recently enough

        queue.append(QueuedProgram(
            handle=prog.handle,
            program_url=prog.program_url,
            in_scope=in_scope,
            out_of_scope=prog.out_of_scope,
            priority=priority,
            roi_score=prog.roi_score,
            is_new=is_new,
            scope_changed=(priority == ScanPriority.SCOPE_CHANGE),
        ))

    queue.sort(key=lambda p: p.sort_key, reverse=True)
    return queue[:max_programs]


def _detect_scope_change(db: Any, handle: str, new_hash: str) -> bool:
    """Check if scope hash changed from what's stored in DB."""
    records = db.get_programs_due(0)  # all programs
    for r in records:
        if r["handle"] == handle:
            return r.get("scope_hash") != new_hash
    return False


def finding_hash(title: str, asset: str, program_handle: str) -> str:
    """Stable deduplication key for a finding."""
    return hashlib.sha256(
        f"{title}|{asset}|{program_handle}".encode()
    ).hexdigest()[:20]
