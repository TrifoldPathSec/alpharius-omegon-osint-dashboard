"""Match your own Wazuh data against the threat intel.

* Alerts: pull IPs, domains and URLs out of alert fields and look them up in the
  indicator table ("did anything in my lab talk to a known-bad host?").
* Vulnerabilities: check the CVEs Wazuh's vulnerability detector found against
  CISA KEV ("am I running something that's being actively exploited?").

Input is either a file (alerts.json lines, a JSON array, or a saved indexer
search response) or a live query to the Wazuh indexer.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from .db import utcnow

IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
DOMAIN_FIELDS = {"hostname", "domain", "queryname", "query", "dns_query", "host", "server_name", "sni"}


# ---------- loading ----------

def load_docs(path: str) -> List[dict]:
    """Accept JSON lines, a JSON array, or an indexer _search response."""
    text = Path(path).read_text()
    stripped = text.lstrip()
    if stripped.startswith("{") and '"hits"' in stripped[:2000]:
        try:
            data = json.loads(stripped)
            return [h.get("_source", h) for h in data["hits"]["hits"]]
        except (json.JSONDecodeError, KeyError):
            pass
    if stripped.startswith("["):
        return [d.get("_source", d) for d in json.loads(stripped)]
    docs = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                docs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return docs


def _indexer_search(http, settings, index: str, body: dict) -> List[dict]:
    if not settings.wazuh_url:
        raise RuntimeError("WAZUH_INDEXER_URL is not set")
    resp = http.post(f"{settings.wazuh_url}/{index}/_search", json=body,
                     auth=(settings.wazuh_user, settings.wazuh_password),
                     verify=settings.wazuh_verify, timeout=30)
    resp.raise_for_status()
    return [h["_source"] for h in resp.json()["hits"]["hits"]]


def fetch_alerts(http, settings, hours: int = 24, size: int = 5000) -> List[dict]:
    body = {"size": size, "sort": [{"timestamp": "desc"}],
            "query": {"range": {"timestamp": {"gte": f"now-{hours}h"}}}}
    return _indexer_search(http, settings, "wazuh-alerts-*", body)


def fetch_vulns(http, settings, size: int = 10000) -> List[dict]:
    return _indexer_search(http, settings, "wazuh-states-vulnerabilities-*",
                           {"size": size, "query": {"match_all": {}}})


# ---------- alert matching ----------

def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _walk(obj, path: str = "") -> Iterator[Tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, path)
    elif isinstance(obj, str):
        yield path, obj


def extract_observables(alert: dict) -> Set[Tuple[str, str]]:
    """Return {(field, value)} of public IPs, URLs and domain-like fields in an alert."""
    found: Set[Tuple[str, str]] = set()
    for field, text in _walk(alert.get("data", {}), "data"):
        for url in URL_RE.findall(text):
            url = url.rstrip(".,;)")
            found.add((field, url))
            host = urlsplit(url).hostname
            if host:
                found.add((field, host.lower()))
        for ip in IPV4_RE.findall(text):
            if _public(ip):
                found.add((field, ip))
        leaf = field.rsplit(".", 1)[-1].lower()
        if leaf in DOMAIN_FIELDS and "." in text and " " not in text and not IPV4_RE.fullmatch(text):
            found.add((field, text.lower().rstrip(".")))
    full_log = alert.get("full_log", "")
    if isinstance(full_log, str):
        for ip in IPV4_RE.findall(full_log):
            if _public(ip):
                found.add(("full_log", ip))
        for url in URL_RE.findall(full_log):
            found.add(("full_log", url.rstrip(".,;)")))
    return found


def match_alerts(conn: sqlite3.Connection, alerts: Iterable[dict]) -> dict:
    scanned = 0
    now = utcnow()
    before = conn.execute("SELECT COUNT(*) FROM alert_matches").fetchone()[0]
    for alert in alerts:
        scanned += 1
        obs = extract_observables(alert)
        if not obs:
            continue
        rule = alert.get("rule", {}) or {}
        agent = (alert.get("agent", {}) or {}).get("name")
        alert_id = str(alert.get("id") or alert.get("_id") or
                       hashlib.sha1(json.dumps(alert, sort_keys=True).encode()).hexdigest()[:16])
        ts = (alert.get("timestamp") or "")[:19].replace("T", " ") or None
        for field, value in obs:
            # Exact match always counts. A host match counts only for IPs: a listed URL
            # on github.com shouldn't flag every alert that mentions github.com.
            if _public(value):
                sql, args = "SELECT source, threat, malware FROM indicators WHERE value=? OR host=? LIMIT 5", (value, value)
            else:
                sql, args = "SELECT source, threat, malware FROM indicators WHERE value=? LIMIT 5", (value,)
            for hit in conn.execute(sql, args):
                conn.execute(
                    """INSERT OR IGNORE INTO alert_matches
                       (alert_id, alert_time, rule_id, rule_desc, agent, field, value, source, threat, malware, matched_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (alert_id, ts, str(rule.get("id", "")), rule.get("description"), agent, field, value,
                     hit["source"], hit["threat"], hit["malware"], now))
    conn.commit()
    new = conn.execute("SELECT COUNT(*) FROM alert_matches").fetchone()[0] - before
    return {"alerts_scanned": scanned, "new_matches": new}


# ---------- vulnerability / KEV matching ----------

def _vuln_fields(doc: dict) -> Optional[dict]:
    vuln = doc.get("vulnerability") or {}
    cve = vuln.get("id") or vuln.get("cve") or (doc.get("data", {}).get("vulnerability", {}) or {}).get("cve")
    if not cve:
        return None
    pkg = doc.get("package") or vuln.get("package") or \
        (doc.get("data", {}).get("vulnerability", {}) or {}).get("package") or {}
    return {
        "agent": (doc.get("agent") or {}).get("name") or "unknown",
        "cve_id": cve.upper(),
        "package": pkg.get("name"),
        "version": pkg.get("version"),
        "severity": vuln.get("severity"),
        "detected_at": vuln.get("detected_at"),
    }


def match_vulns(conn: sqlite3.Connection, docs: Iterable[dict]) -> dict:
    scanned = 0
    now = utcnow()
    before = conn.execute("SELECT COUNT(*) FROM vuln_matches").fetchone()[0]
    for doc in docs:
        v = _vuln_fields(doc)
        if not v:
            continue
        scanned += 1
        kev = conn.execute("SELECT ransomware, due_date FROM kev WHERE cve_id=?", (v["cve_id"],)).fetchone()
        if not kev:
            continue
        conn.execute(
            """INSERT INTO vuln_matches
               (agent, cve_id, package, version, severity, detected_at, ransomware, due_date, matched_at)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(agent, cve_id, package) DO UPDATE SET version=excluded.version,
                   severity=excluded.severity, matched_at=excluded.matched_at""",
            (v["agent"], v["cve_id"], v["package"], v["version"], v["severity"], v["detected_at"],
             kev["ransomware"], kev["due_date"], now))
    conn.commit()
    new = conn.execute("SELECT COUNT(*) FROM vuln_matches").fetchone()[0] - before
    return {"vulns_scanned": scanned, "new_matches": new}
