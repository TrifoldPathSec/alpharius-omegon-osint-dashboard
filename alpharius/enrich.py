"""IOC enrichment: take one indicator (IP, domain, URL or hash), gather context
from the local feed database and public services, and score it 0-100.

Passive checks (always): local feed hits, RDAP/WHOIS, DNS, ipinfo.io,
AbuseIPDB and VirusTotal (when keys are set).
Active checks (opt-in): follow the URL's redirect chain, read response headers
and pull the TLS certificate. These touch the indicator's infrastructure, so
they're off by default and refuse anything that resolves to a private address.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import sqlite3
import ssl
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from .config import USER_AGENT
from .db import utcnow

HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I)
SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy"]
MAX_REDIRECTS = 8


class EnrichError(ValueError):
    pass


# ---------- input handling ----------

def refang(value: str) -> str:
    """Undo common defanging: hxxp://, [.], (.), [:]"""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":"), ("[://]", "://")):
        v = v.replace(a, b)
    return v


def classify(value: str) -> Tuple[str, str]:
    """Return (normalized_value, type). Raises EnrichError for anything else."""
    v = refang(value)
    if not v or len(v) > 2048 or any(c.isspace() for c in v):
        raise EnrichError("Enter a single IP, domain, URL or file hash.")
    if HASH_RE.match(v):
        return v.lower(), "hash"
    try:
        return str(ipaddress.ip_address(v)), "ip"
    except ValueError:
        pass
    if re.match(r"^https?://", v, re.I):
        host = urlsplit(v).hostname
        if not host:
            raise EnrichError("URL has no host.")
        return v, "url"
    if DOMAIN_RE.match(v):
        return v.lower().rstrip("."), "domain"
    raise EnrichError("Not a recognisable IP, domain, URL or MD5/SHA1/SHA256 hash.")


def _is_ip(value: Optional[str]) -> bool:
    try:
        ipaddress.ip_address(value or "")
        return True
    except ValueError:
        return False


_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "ne", "or"}


def base_domain(host: str) -> str:
    """Rough registrable domain (no public-suffix list): a.b.example.co.uk -> example.co.uk"""
    if _is_ip(host):
        return host
    labels = host.lower().rstrip(".").split(".")
    n = 3 if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2 else 2
    return ".".join(labels[-n:])


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_global and not addr.is_multicast


# ---------- default network helpers (swapped out in tests) ----------

def default_resolve(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({i[4][0] for i in infos})


def default_dns_query(name: str, rtype: str) -> List[str]:
    import dns.exception
    import dns.resolver
    try:
        answer = dns.resolver.resolve(name, rtype, lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return []
    return [r.to_text().strip('"') for r in answer]


def default_tls_fetch(host: str, port: int = 443, timeout: float = 8.0) -> Tuple[bytes, bool, str]:
    """Return (DER certificate, trusted?, trust error). Retrieves untrusted certs too."""
    trusted, err = True, ""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLError as exc:
        trusted, err = False, getattr(exc, "verify_message", None) or str(exc)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    return der, trusted, err


# ---------- helpers ----------

def _parse_date(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _days_since(dt: Optional[datetime], now: datetime) -> Optional[int]:
    return None if dt is None else (now - dt).days


def _host_matches(host: str, names: List[str]) -> bool:
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") >= n.count(".") and host.endswith(n[1:]) \
                and host[: -len(n) + 1].count(".") == 0:
            return True
    return False


def _registrar_from_rdap(data: dict) -> Optional[str]:
    for ent in data.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    return item[3]
            return ent.get("handle")
    return None


class Enricher:
    def __init__(self, conn: sqlite3.Connection, http, settings,
                 resolve: Callable[[str], List[str]] = default_resolve,
                 dns_query: Callable[[str, str], List[str]] = default_dns_query,
                 tls_fetch: Callable[..., Tuple[bytes, bool, str]] = default_tls_fetch,
                 now: Optional[datetime] = None):
        self.conn, self.http, self.s = conn, http, settings
        self.resolve, self.dns_query, self.tls_fetch = resolve, dns_query, tls_fetch
        self.now = now or datetime.now(timezone.utc)
        self.timeout = getattr(settings, "http_timeout", 20.0)

    # ----- passive -----

    def feed_hits(self, value: str, kind: str) -> dict:
        """Exact hits (the indicator itself, or the URL's host, is listed) are strong.
        "Hosted" hits (other listed URLs live on the same host) are weaker: big
        platforms like github.com always host some malware URLs."""
        cols = "value, type, source, threat, malware, status, first_seen, last_seen, reference"
        host = urlsplit(value).hostname.lower() if kind == "url" else (value if kind in ("ip", "domain") else None)
        exact_keys = {value if kind == "url" else value.lower()}
        if kind == "url" and host:
            exact_keys.add(host)
        exact = self.conn.execute(
            f"SELECT {cols} FROM indicators WHERE value IN ({','.join('?' * len(exact_keys))}) "
            "ORDER BY first_seen DESC LIMIT 50", list(exact_keys)).fetchall()
        hosted, total = [], 0
        if host:
            total = self.conn.execute(
                "SELECT COUNT(*) FROM indicators WHERE type='url' AND host=? AND value != ?",
                (host, value)).fetchone()[0]
            hosted = self.conn.execute(
                f"SELECT {cols} FROM indicators WHERE type='url' AND host=? AND value != ? "
                "ORDER BY first_seen DESC LIMIT 10", (host, value)).fetchall()
        return {"exact": [dict(r) for r in exact], "hosted": [dict(r) for r in hosted],
                "hosted_total": total, "host": host, "host_is_ip": _is_ip(host)}

    def rdap_domain(self, domain: str) -> dict:
        labels = domain.split(".")
        for i in range(0, max(1, len(labels) - 1)):
            candidate = ".".join(labels[i:])
            resp = self.http.get(f"https://rdap.org/domain/{candidate}", timeout=self.timeout,
                                 headers={"Accept": "application/rdap+json"})
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            data = resp.json()
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) or []}
            created = _parse_date(events.get("registration"))
            return {
                "domain": candidate,
                "registrar": _registrar_from_rdap(data),
                "created": events.get("registration"),
                "expires": events.get("expiration"),
                "updated": events.get("last changed"),
                "age_days": _days_since(created, self.now),
                "status": data.get("status", []),
                "nameservers": [n.get("ldhName", "").lower() for n in data.get("nameservers", []) or []],
            }
        return {"error": "no RDAP record found"}

    def rdap_ip(self, ip: str) -> dict:
        resp = self.http.get(f"https://rdap.org/ip/{ip}", timeout=self.timeout,
                             headers={"Accept": "application/rdap+json"})
        resp.raise_for_status()
        d = resp.json()
        return {"network": d.get("name"), "handle": d.get("handle"), "country": d.get("country"),
                "range": f"{d.get('startAddress')} - {d.get('endAddress')}"}

    def dns(self, host: str) -> dict:
        out = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            records = self.dns_query(host, rtype)
            if records:
                out[rtype] = records[:10]
        return out

    def ipinfo(self, ip: str) -> dict:
        params = {"token": self.s.ipinfo_token} if self.s.ipinfo_token else {}
        resp = self.http.get(f"https://ipinfo.io/{ip}/json", params=params, timeout=self.timeout)
        resp.raise_for_status()
        d = resp.json()
        return {k: d.get(k) for k in ("ip", "hostname", "org", "country", "region", "city")}

    def abuseipdb(self, ip: str) -> dict:
        resp = self.http.get("https://api.abuseipdb.com/api/v2/check",
                             params={"ipAddress": ip, "maxAgeInDays": 90},
                             headers={"Key": self.s.abuseipdb_key, "Accept": "application/json"},
                             timeout=self.timeout)
        resp.raise_for_status()
        d = resp.json().get("data", {})
        return {k: d.get(k) for k in ("abuseConfidenceScore", "totalReports", "countryCode",
                                      "isp", "usageType", "lastReportedAt")}

    def virustotal(self, value: str, kind: str) -> dict:
        if kind == "url":
            ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            path = f"urls/{ident}"
        else:
            path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[kind] + f"/{value}"
        resp = self.http.get(f"https://www.virustotal.com/api/v3/{path}",
                             headers={"x-apikey": self.s.virustotal_key}, timeout=self.timeout)
        if resp.status_code == 404:
            return {"found": False}
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {"found": True, "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0), "reputation": attrs.get("reputation"),
                "meaningful_name": attrs.get("meaningful_name")}

    # ----- active -----

    def _guard(self, host: str) -> List[str]:
        try:
            addrs = [str(ipaddress.ip_address(host))]
        except ValueError:
            addrs = self.resolve(host)
        if not addrs:
            raise EnrichError(f"{host} does not resolve")
        bad = [a for a in addrs if not is_public_ip(a)]
        if bad:
            raise EnrichError(f"refusing to contact {host}: resolves to non-public address {bad[0]}")
        return addrs

    def http_probe(self, url: str) -> dict:
        chain, current = [], url
        resp = None
        for _ in range(MAX_REDIRECTS + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                chain.append({"url": current, "status": None, "note": "non-HTTP redirect target, stopped"})
                break
            self._guard(parts.hostname)
            resp = self.http.get(current, allow_redirects=False, stream=True, timeout=self.timeout,
                                 headers={"User-Agent": USER_AGENT})
            resp.close()
            hop = {"url": current, "status": resp.status_code, "server": resp.headers.get("Server")}
            loc = resp.headers.get("Location")
            if resp.status_code in (301, 302, 303, 307, 308) and loc:
                hop["location"] = urljoin(current, loc)
                chain.append(hop)
                current = hop["location"]
                continue
            chain.append(hop)
            break
        headers = {k.lower(): v for k, v in (resp.headers.items() if resp is not None else [])}
        keep = ["server", "content-type", "x-powered-by", "set-cookie", "via", "cf-ray"]
        first, last = urlsplit(url).hostname, urlsplit(current).hostname
        return {
            "chain": chain,
            "hops": max(0, len(chain) - 1),
            "final_url": current,
            "cross_domain": bool(first and last and base_domain(first) != base_domain(last)),
            "headers": {k: headers[k][:200] for k in keep if k in headers},
            "missing_security_headers": [h for h in SECURITY_HEADERS if h not in headers],
        }

    def tls(self, host: str) -> dict:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID

        self._guard(host)
        der, trusted, trust_err = self.tls_fetch(host, 443)
        cert = x509.load_der_x509_certificate(der)

        def name_attr(name, oid):
            vals = name.get_attributes_for_oid(oid)
            return vals[0].value if vals else None

        try:
            sans = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        subject_cn = name_attr(cert.subject, NameOID.COMMON_NAME)
        names = list(sans) or ([subject_cn] if subject_cn else [])
        return {
            "subject_cn": subject_cn,
            "issuer_cn": name_attr(cert.issuer, NameOID.COMMON_NAME),
            "issuer_org": name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
            "sans": sans[:25],
            "not_before": nb.strftime("%Y-%m-%d"),
            "not_after": na.strftime("%Y-%m-%d"),
            "age_days": (self.now - nb).days,
            "days_left": (na - self.now).days,
            "self_signed": cert.issuer == cert.subject,
            "hostname_match": _host_matches(host, names),
            "trusted": trusted,
            "trust_error": trust_err or None,
        }

    # ----- orchestration -----

    def run(self, raw: str, active: bool = False) -> dict:
        value, kind = classify(raw)
        active = active and kind in ("url", "domain")  # nothing to fetch for an IP or a hash
        result: Dict[str, object] = {"indicator": value, "type": kind, "active": active,
                                     "checked_at": utcnow(), "errors": {}}
        errors: Dict[str, str] = result["errors"]  # type: ignore[assignment]

        def attempt(section: str, fn, *args):
            try:
                result[section] = fn(*args)
            except Exception as exc:
                errors[section] = str(exc)[:200]

        host = urlsplit(value).hostname if kind == "url" else (value if kind in ("ip", "domain") else None)
        host_is_ip = _is_ip(host)

        attempt("feeds", self.feed_hits, value, kind)

        ip_for_lookup = None
        if host and host_is_ip:
            if is_public_ip(host):
                ip_for_lookup = host
                attempt("rdap", self.rdap_ip, host)
        elif host:
            attempt("rdap", self.rdap_domain, host)
            attempt("dns", self.dns, host)
            a_records = (result.get("dns") or {}).get("A", [])  # type: ignore[union-attr]
            ip_for_lookup = next((a for a in a_records if is_public_ip(a)), None)

        if ip_for_lookup and is_public_ip(ip_for_lookup):
            attempt("ipinfo", self.ipinfo, ip_for_lookup)
            if self.s.abuseipdb_key:
                attempt("abuseipdb", self.abuseipdb, ip_for_lookup)
        if self.s.virustotal_key:
            attempt("virustotal", self.virustotal, value, kind)

        if active and kind in ("url", "domain"):
            url = value if kind == "url" else f"https://{value}/"
            attempt("http", self.http_probe, url)
            final = (result.get("http") or {}).get("final_url", url)  # type: ignore[union-attr]
            tls_host = urlsplit(final).hostname if final.startswith("https://") else None
            if tls_host:
                attempt("tls", self.tls, tls_host)

        score, reasons = score_result(result)
        result["score"], result["reasons"] = score, reasons
        result["verdict"] = verdict_for(score)
        return result


def score_result(r: dict) -> Tuple[int, List[str]]:
    """Additive, explainable scoring. Every point comes with a reason."""
    pts: List[Tuple[int, str]] = []
    feeds = r.get("feeds") or {}
    exact = feeds.get("exact") or []
    if exact:
        sources = sorted({f["source"] for f in exact})
        pts.append((70, f"listed in threat feed(s): {', '.join(sources)}"))
        if any(f["source"] == "feodo" and f.get("status") == "online" for f in exact):
            pts.append((10, "botnet C2 currently online (Feodo Tracker)"))
    elif feeds.get("hosted_total"):
        n = feeds["hosted_total"]
        if feeds.get("host_is_ip"):
            pts.append((40, f"{n} listed malware URL(s) served from this IP"))
        else:
            pts.append((15, f"{n} listed malware URL(s) hosted on this domain (may be an abused shared platform)"))
    abuse = r.get("abuseipdb") or {}
    conf = abuse.get("abuseConfidenceScore") or 0
    if conf >= 75:
        pts.append((40, f"AbuseIPDB confidence {conf}%"))
    elif conf >= 25:
        pts.append((20, f"AbuseIPDB confidence {conf}%"))
    vt = r.get("virustotal") or {}
    mal = vt.get("malicious") or 0
    if mal >= 3:
        pts.append((50, f"{mal} VirusTotal engines flag it malicious"))
    elif mal >= 1:
        pts.append((25, f"{mal} VirusTotal engine(s) flag it malicious"))
    elif (vt.get("suspicious") or 0) >= 1:
        pts.append((10, "VirusTotal engines flag it suspicious"))
    age = (r.get("rdap") or {}).get("age_days")
    if age is not None and age < 30:
        pts.append((25, f"domain registered {age} days ago"))
    elif age is not None and age < 180:
        pts.append((10, f"domain registered {age} days ago"))
    tls = r.get("tls") or {}
    if tls:
        if tls.get("self_signed"):
            pts.append((10, "self-signed TLS certificate"))
        elif not tls.get("trusted"):
            pts.append((10, "TLS certificate not trusted"))
        if not tls.get("hostname_match"):
            pts.append((15, "TLS certificate doesn't match the hostname"))
        if tls.get("age_days") is not None and tls["age_days"] < 7:
            pts.append((10, f"TLS certificate issued {tls['age_days']} days ago"))
    http = r.get("http") or {}
    if http.get("hops", 0) >= 3:
        pts.append((10, f"{http['hops']} redirects before landing"))
    if http.get("cross_domain"):
        pts.append((5, "redirects to a different domain"))
    score = min(100, sum(p for p, _ in pts))
    return score, [f"+{p} {why}" for p, why in pts]


def verdict_for(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "low"


def save_lookup(conn: sqlite3.Connection, result: dict) -> int:
    lookup_id = conn.execute(
        "INSERT INTO lookups (indicator, type, score, verdict, result_json, created_at) VALUES (?,?,?,?,?,?)",
        (result["indicator"], result["type"], result["score"], result["verdict"],
         json.dumps(result, default=str), utcnow())).lastrowid
    conn.commit()
    return lookup_id
