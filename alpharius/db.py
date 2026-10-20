"""SQLite storage: schema, connection helper and the queries the dashboard charts use."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    id          INTEGER PRIMARY KEY,
    value       TEXT NOT NULL,
    type        TEXT NOT NULL,          -- ip | domain | url | hash
    host        TEXT,                   -- host part of a URL, or the IP/domain itself
    source      TEXT NOT NULL,          -- urlhaus | threatfox | feodo
    threat      TEXT,
    malware     TEXT,
    tags        TEXT,
    status      TEXT,
    country     TEXT,
    confidence  INTEGER,
    reference   TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    ingested_at TEXT NOT NULL,
    UNIQUE (value, source)
);
CREATE INDEX IF NOT EXISTS ix_indicators_host ON indicators(host);
CREATE INDEX IF NOT EXISTS ix_indicators_first_seen ON indicators(first_seen);

CREATE TABLE IF NOT EXISTS kev (
    cve_id          TEXT PRIMARY KEY,
    vendor          TEXT,
    product         TEXT,
    name            TEXT,
    description     TEXT,
    required_action TEXT,
    date_added      TEXT,
    due_date        TEXT,
    ransomware      TEXT
);

CREATE TABLE IF NOT EXISTS ingest_runs (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL,
    fetched     INTEGER DEFAULT 0,
    new         INTEGER DEFAULT 0,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS lookups (
    id          INTEGER PRIMARY KEY,
    indicator   TEXT NOT NULL,
    type        TEXT NOT NULL,
    score       INTEGER NOT NULL,
    verdict     TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_matches (
    id          INTEGER PRIMARY KEY,
    alert_id    TEXT NOT NULL,
    alert_time  TEXT,
    rule_id     TEXT,
    rule_desc   TEXT,
    agent       TEXT,
    field       TEXT,
    value       TEXT NOT NULL,
    source      TEXT,
    threat      TEXT,
    malware     TEXT,
    matched_at  TEXT NOT NULL,
    UNIQUE (alert_id, value, source)
);

CREATE TABLE IF NOT EXISTS vuln_matches (
    id          INTEGER PRIMARY KEY,
    agent       TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    package     TEXT,
    version     TEXT,
    severity    TEXT,
    detected_at TEXT,
    ransomware  TEXT,
    due_date    TEXT,
    matched_at  TEXT NOT NULL,
    UNIQUE (agent, cve_id, package)
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def connect(path: str) -> sqlite3.Connection:
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


# ---------- dashboard queries ----------

def overview_counts(conn: sqlite3.Connection) -> dict:
    one = lambda sql, *a: conn.execute(sql, a).fetchone()[0]  # noqa: E731
    return {
        "indicators": one("SELECT COUNT(*) FROM indicators"),
        "new_24h": one("SELECT COUNT(*) FROM indicators WHERE first_seen >= datetime('now','-1 day')"),
        "online_c2": one("SELECT COUNT(*) FROM indicators WHERE source='feodo' AND status='online'"),
        "kev": one("SELECT COUNT(*) FROM kev"),
        "kev_ransomware": one("SELECT COUNT(*) FROM kev WHERE ransomware='Known'"),
        "alert_matches": one("SELECT COUNT(*) FROM alert_matches"),
        "vuln_matches": one("SELECT COUNT(*) FROM vuln_matches"),
        "lookups": one("SELECT COUNT(*) FROM lookups"),
    }


def daily_new_by_source(conn: sqlite3.Connection, days: int = 30) -> dict:
    rows = conn.execute(
        """SELECT substr(first_seen,1,10) AS day, source, COUNT(*) AS n
           FROM indicators
           WHERE first_seen >= date('now', ?)
           GROUP BY day, source ORDER BY day""",
        (f"-{days} day",),
    ).fetchall()
    labels = sorted({r["day"] for r in rows})
    sources = sorted({r["source"] for r in rows})
    grid = {s: {d: 0 for d in labels} for s in sources}
    for r in rows:
        grid[r["source"]][r["day"]] = r["n"]
    return {"labels": labels, "series": {s: [grid[s][d] for d in labels] for s in sources}}


def top_malware(conn: sqlite3.Connection, limit: int = 10) -> list:
    return [dict(r) for r in conn.execute(
        """SELECT malware AS label, COUNT(*) AS n FROM indicators
           WHERE malware IS NOT NULL AND malware != '' AND malware NOT LIKE 'Unknown %'
           GROUP BY malware ORDER BY n DESC LIMIT ?""", (limit,))]


def c2_countries(conn: sqlite3.Connection, limit: int = 10) -> list:
    return [dict(r) for r in conn.execute(
        """SELECT country AS label, COUNT(*) AS n FROM indicators
           WHERE source='feodo' AND country IS NOT NULL AND country != ''
           GROUP BY country ORDER BY n DESC LIMIT ?""", (limit,))]


def type_breakdown(conn: sqlite3.Connection) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT type AS label, COUNT(*) AS n FROM indicators GROUP BY type ORDER BY n DESC")]


def kev_by_month(conn: sqlite3.Connection, months: int = 24) -> dict:
    rows = conn.execute(
        """SELECT substr(date_added,1,7) AS month, COUNT(*) AS n,
                  SUM(CASE WHEN ransomware='Known' THEN 1 ELSE 0 END) AS ransomware
           FROM kev WHERE date_added >= date('now', ?)
           GROUP BY month ORDER BY month""",
        (f"-{months} month",),
    ).fetchall()
    return {
        "labels": [r["month"] for r in rows],
        "total": [r["n"] for r in rows],
        "ransomware": [r["ransomware"] for r in rows],
    }


def matches_by_day(conn: sqlite3.Connection, days: int = 30) -> dict:
    rows = conn.execute(
        """SELECT substr(COALESCE(alert_time, matched_at),1,10) AS day, COUNT(*) AS n
           FROM alert_matches WHERE COALESCE(alert_time, matched_at) >= date('now', ?)
           GROUP BY day ORDER BY day""",
        (f"-{days} day",),
    ).fetchall()
    return {"labels": [r["day"] for r in rows], "counts": [r["n"] for r in rows]}


def recent_runs(conn: sqlite3.Connection, limit: int = 8) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM ingest_runs ORDER BY id DESC LIMIT ?", (limit,))]
