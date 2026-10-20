"""Public threat-feed collectors.

Each feed has a pure parser (text -> list of rows, easy to unit-test) and is
fetched by ``ingest()``, which upserts into SQLite and logs an ingest run.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import sqlite3
from typing import Callable, Dict, List, Optional
from urllib.parse import urlsplit

from .db import utcnow

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def url_host(url: str) -> Optional[str]:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return normalise_ip(host.lower()) if host else None


def normalise_ip(value: str) -> str:
    """IPv6 literals in compressed lower-case form (what Wazuh matching
    produces); anything else unchanged."""
    if ":" in value:
        try:
            return ipaddress.IPv6Address(value).compressed
        except ValueError:
            pass
    return value


def _ip_without_port(raw: str) -> str:
    """ThreatFox "ip:port" values: "1.2.3.4:80" or "[2001:db8::1]:443"."""
    if raw.startswith("["):
        return normalise_ip(raw[1:].split("]", 1)[0])
    if raw.count(":") > 1:  # bare IPv6, no port
        return normalise_ip(raw)
    return raw.rsplit(":", 1)[0]


def _clean(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = str(value).strip()
    return None if value in ("", "None", "null") else value


# ---------- parsers ----------

def parse_urlhaus(text: str) -> List[dict]:
    lines = [l for l in text.splitlines() if l and not l.startswith("#")]
    cols = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
    rows = []
    for rec in csv.reader(io.StringIO("\n".join(lines))):
        if len(rec) < len(cols):
            continue
        r = dict(zip(cols, rec))
        rows.append({
            "value": r["url"],
            "type": "url",
            "host": url_host(r["url"]),
            "source": "urlhaus",
            "threat": _clean(r["threat"]),
            "malware": None,
            "tags": _clean(r["tags"]),
            "status": _clean(r["url_status"]),
            "country": None,
            "confidence": None,
            "reference": _clean(r["urlhaus_link"]),
            "first_seen": _clean(r["dateadded"]),
            "last_seen": _clean(r["last_online"]),
        })
    return rows


_THREATFOX_TYPES = {
    "ip:port": "ip", "domain": "domain", "url": "url",
    "md5_hash": "hash", "sha1_hash": "hash", "sha256_hash": "hash",
}


def parse_threatfox(text: str) -> List[dict]:
    data = json.loads(text)
    rows = []
    for entries in data.values():
        for e in entries:
            kind = _THREATFOX_TYPES.get(e.get("ioc_type", ""))
            if not kind:
                continue
            raw = e["ioc_value"].strip()
            value = _ip_without_port(raw) if kind == "ip" else raw
            host = url_host(value) if kind == "url" else (value.lower() if kind in ("ip", "domain") else None)
            rows.append({
                "value": value,
                "type": kind,
                "host": host,
                "source": "threatfox",
                "threat": _clean(e.get("threat_type")),
                "malware": _clean(e.get("malware_printable")),
                "tags": _clean(e.get("tags")),
                "status": None,
                "country": None,
                "confidence": e.get("confidence_level"),
                "reference": _clean(e.get("reference")),
                "first_seen": _clean(e.get("first_seen_utc")),
                "last_seen": _clean(e.get("last_seen_utc")),
            })
    return rows


def parse_feodo(text: str) -> List[dict]:
    rows = []
    for e in json.loads(text):
        ip = e["ip_address"].strip()
        tags = ",".join(filter(None, [f"port:{e.get('port')}" if e.get("port") else None, _clean(e.get("as_name"))]))
        rows.append({
            "value": ip,
            "type": "ip",
            "host": ip,
            "source": "feodo",
            "threat": "botnet_cc",
            "malware": _clean(e.get("malware")),
            "tags": tags or None,
            "status": _clean(e.get("status")),
            "country": _clean(e.get("country")),
            "confidence": None,
            "reference": f"https://feodotracker.abuse.ch/browse/host/{ip}/",
            "first_seen": _clean(e.get("first_seen")),
            "last_seen": _clean(e.get("last_online")),
        })
    return rows


def parse_kev(text: str) -> List[dict]:
    data = json.loads(text)
    return [{
        "cve_id": v["cveID"],
        "vendor": v.get("vendorProject"),
        "product": v.get("product"),
        "name": v.get("vulnerabilityName"),
        "description": v.get("shortDescription"),
        "required_action": v.get("requiredAction"),
        "date_added": v.get("dateAdded"),
        "due_date": v.get("dueDate"),
        "ransomware": v.get("knownRansomwareCampaignUse"),
    } for v in data.get("vulnerabilities", [])]


# ---------- storage ----------

_IND_COLS = ["value", "type", "host", "source", "threat", "malware", "tags", "status",
             "country", "confidence", "reference", "first_seen", "last_seen"]


def store_indicators(conn: sqlite3.Connection, rows: List[dict]) -> int:
    """Upsert indicators; returns how many were new."""
    before = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    now = utcnow()
    conn.executemany(
        f"""INSERT INTO indicators ({", ".join(_IND_COLS)}, ingested_at)
            VALUES ({", ".join("?" * len(_IND_COLS))}, ?)
            ON CONFLICT(value, source) DO UPDATE SET
                status=excluded.status, last_seen=excluded.last_seen,
                tags=excluded.tags, malware=COALESCE(excluded.malware, indicators.malware)""",
        [[r.get(c) for c in _IND_COLS] + [now] for r in rows],
    )
    conn.commit()
    return conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] - before


def store_kev(conn: sqlite3.Connection, rows: List[dict]) -> int:
    before = conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
    cols = ["cve_id", "vendor", "product", "name", "description", "required_action",
            "date_added", "due_date", "ransomware"]
    conn.executemany(
        f"INSERT OR REPLACE INTO kev ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
        [[r.get(c) for c in cols] for r in rows],
    )
    conn.commit()
    return conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0] - before


# ---------- ingest ----------

FEEDS: Dict[str, tuple] = {
    "urlhaus": (URLHAUS_URL, parse_urlhaus, store_indicators),
    "threatfox": (THREATFOX_URL, parse_threatfox, store_indicators),
    "feodo": (FEODO_URL, parse_feodo, store_indicators),
    "kev": (KEV_URL, parse_kev, store_kev),
}


def ingest(conn: sqlite3.Connection, http, sources: Optional[List[str]] = None,
           abusech_key: str = "", timeout: float = 60.0,
           log: Callable[[str], None] = lambda m: None) -> List[dict]:
    """Fetch, parse and store each feed. One failing feed doesn't stop the others."""
    results = []
    for name in sources or list(FEEDS):
        url, parse, store = FEEDS[name]
        started = utcnow()
        run_id = conn.execute(
            "INSERT INTO ingest_runs (source, started_at, status) VALUES (?, ?, 'running')",
            (name, started)).lastrowid
        conn.commit()
        headers = {"Auth-Key": abusech_key} if abusech_key and "abuse.ch" in url else {}
        try:
            resp = http.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            rows = parse(resp.text)
            new = store(conn, rows)
            conn.execute(
                "UPDATE ingest_runs SET finished_at=?, status='ok', fetched=?, new=? WHERE id=?",
                (utcnow(), len(rows), new, run_id))
            result = {"source": name, "status": "ok", "fetched": len(rows), "new": new}
        except Exception as exc:  # network, HTTP or parse error
            conn.execute(
                "UPDATE ingest_runs SET finished_at=?, status='error', error=? WHERE id=?",
                (utcnow(), str(exc)[:500], run_id))
            result = {"source": name, "status": "error", "error": str(exc)[:200]}
        conn.commit()
        log(f"{name}: {result}")
        results.append(result)
    return results
