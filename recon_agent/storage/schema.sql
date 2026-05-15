-- recon-agent SQLite schema

CREATE TABLE IF NOT EXISTS runs (
    id          TEXT PRIMARY KEY,
    program_url TEXT NOT NULL,
    started_at  REAL NOT NULL,
    ended_at    REAL,
    status      TEXT NOT NULL DEFAULT 'running',
    cost_usd    REAL DEFAULT 0.0,
    iterations  INTEGER DEFAULT 0,
    run_dir     TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL REFERENCES runs(id),
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    asset       TEXT NOT NULL,
    description TEXT,
    evidence    TEXT,
    poc         TEXT,
    impact      TEXT,
    remediation TEXT,
    cwe         TEXT,
    cvss        REAL,
    source_tool TEXT,
    confidence  REAL,
    false_positive INTEGER DEFAULT 0,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL REFERENCES runs(id),
    tool        TEXT NOT NULL,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    duration_s  REAL,
    iteration   INTEGER,
    executed_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL REFERENCES runs(id),
    event       TEXT NOT NULL,
    ts          REAL NOT NULL,
    data        TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_actions_run ON actions(run_id);
