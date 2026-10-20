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
import ssl
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter

from .db import utcnow
from .feeds import normalise_ip

IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
DOMAIN_FIELDS = {"hostname", "domain", "queryname", "query", "dns_query", "host", "server_name", "sni",
                 "rrname"}
# Fields that hold IP addresses. IPv6 is only taken from these (no freeform IPv6
# regex over arbitrary text: "::", MACs and timestamps make that too noisy).
IP_FIELDS = {"srcip", "dstip", "src_ip", "dst_ip", "dest_ip", "ip", "ipv6", "address", "addr",
             "answers", "answer", "rdata", "remote_ip", "client_ip", "server_ip"}
# Config-assessment and documentation text mentions URLs that aren't network activity.
SKIP_RULE_GROUPS = {"sca", "rootcheck", "vulnerability-detector"}
SKIP_FIELD_PARTS = {"references", "reference", "rationale", "remediation", "description",
                    "compliance", "policy", "title"}


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


class ServerNameAdapter(HTTPAdapter):
    """Connect to one address but verify the certificate for another name.

    wazuh-docker issues the indexer certificate for "wazuh.indexer" only, so
    connecting by IP would fail hostname verification. This keeps full chain
    verification against the Wazuh root CA and checks the expected name,
    instead of turning verification off."""

    def __init__(self, server_name: str, **kw):
        self.server_name = server_name
        super().__init__(**kw)

    def init_poolmanager(self, *args, **kw):
        kw["assert_hostname"] = self.server_name
        kw["server_hostname"] = self.server_name
        kw["ssl_context"] = lab_ca_context()
        super().init_poolmanager(*args, **kw)


def lab_ca_context() -> ssl.SSLContext:
    """Certificate-verifying context that trusts only the CA file requests passes
    in (no system CAs). It skips VERIFY_X509_STRICT, which newer Python versions
    turn on and which rejects the wazuh-certs-tool root CA because it has no
    keyUsage extension. Chain and hostname are still verified."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # CERT_REQUIRED, no CAs loaded
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    return ctx


def indexer_session(settings, http=None):
    """The HTTP client to use for the indexer: a name-pinned session when
    WAZUH_INDEXER_SERVER_NAME is set, otherwise the shared one."""
    if getattr(settings, "wazuh_server_name", ""):
        session = requests.Session()
        session.mount(f"{settings.wazuh_url}/", ServerNameAdapter(settings.wazuh_server_name))
        return session
    return http or requests.Session()


def _indexer_search(http, settings, index: str, body: dict) -> List[dict]:
    if not settings.wazuh_url:
        raise RuntimeError("WAZUH_INDEXER_URL is not set")
    if not settings.wazuh_user or not settings.wazuh_password:
        raise RuntimeError("WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD are not set "
                           "(run scripts/wazuh_readonly_user.py)")
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


def _ipv6_values(text: str) -> Iterator[str]:
    """Public IPv6 addresses in an IP field value, in compressed form. Accepts
    one address or a comma/space separated list; brackets are stripped and a
    zone id ("%en0") is dropped."""
    for token in re.split(r"[\s,;]+", text):
        token = token.strip("[]").split("%", 1)[0]
        if ":" not in token:
            continue
        try:
            ip = ipaddress.IPv6Address(token)
        except ValueError:
            continue
        if ip.is_global:
            yield ip.compressed


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
    groups = set((alert.get("rule") or {}).get("groups") or [])
    if groups & SKIP_RULE_GROUPS:
        return found
    for field, text in _walk(alert.get("data", {}), "data"):
        if SKIP_FIELD_PARTS & set(field.lower().split(".")):
            continue
        for url in URL_RE.findall(text):
            url = url.rstrip(".,;)")
            found.add((field, url))
            try:
                host = urlsplit(url).hostname
            except ValueError:  # malformed "[...]" host
                host = None
            if host:
                found.add((field, normalise_ip(host.lower())))
        for ip in IPV4_RE.findall(text):
            if _public(ip):
                found.add((field, ip))
        leaf = field.rsplit(".", 1)[-1].lower()
        if leaf in IP_FIELDS:
            for ip in _ipv6_values(text):
                found.add((field, ip))
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
