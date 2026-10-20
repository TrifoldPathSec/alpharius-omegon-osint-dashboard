from datetime import datetime, timedelta, timezone

import pytest
from conftest import FakeHTTP, FakeResponse, fixture_text

from alpharius import enrich, feeds

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
PUBLIC_IP = "93.184.216.34"


@pytest.mark.parametrize("raw,expected", [
    ("8.8.8.8", ("8.8.8.8", "ip")),
    ("hxxp://bad[.]example/login", ("http://bad.example/login", "url")),
    ("Evil-C2.Example", ("evil-c2.example", "domain")),
    ("D41D8CD98F00B204E9800998ECF8427E", ("d41d8cd98f00b204e9800998ecf8427e", "hash")),
    ("2001:db8::1", ("2001:db8::1", "ip")),
])
def test_classify(raw, expected):
    assert enrich.classify(raw) == expected


@pytest.mark.parametrize("raw", ["", "not an indicator", "localhost", "ftp://x.example", "a" * 3000])
def test_classify_rejects(raw):
    with pytest.raises(enrich.EnrichError):
        enrich.classify(raw)


def rdap(days_old):
    created = (NOW - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"events": [{"eventAction": "registration", "eventDate": created}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE"}], "status": ["active"]}


def make_enricher(conn, settings, http, resolve=None, tls_fetch=None):
    return enrich.Enricher(
        conn, http, settings,
        resolve=resolve or (lambda h: [PUBLIC_IP]),
        dns_query=lambda name, rtype: [PUBLIC_IP] if rtype == "A" else [],
        tls_fetch=tls_fetch or (lambda h, p: (_ for _ in ()).throw(RuntimeError("no tls in test"))),
        now=NOW)


def test_known_bad_domain_scores_malicious(conn, settings):
    feeds.store_indicators(conn, feeds.parse_threatfox(fixture_text("threatfox.json")))
    http = FakeHTTP({
        "https://rdap.org/domain/evil-c2.example": FakeResponse(200, rdap(5)),
        f"https://ipinfo.io/{PUBLIC_IP}/json": FakeResponse(200, {"ip": PUBLIC_IP, "org": "AS15133 Edgecast", "country": "US"}),
    })
    r = make_enricher(conn, settings, http).run("evil-c2[.]example")
    assert r["type"] == "domain"
    assert r["feeds"]["exact"][0]["malware"] == "Remcos"
    assert r["rdap"]["age_days"] == 5 and r["rdap"]["registrar"] == "Example Registrar"
    assert r["dns"] == {"A": [PUBLIC_IP]}
    assert r["ipinfo"]["org"].startswith("AS15133")
    assert r["verdict"] == "malicious" and r["score"] == 95
    assert any("registered 5 days ago" in x for x in r["reasons"])


def test_rdap_walks_up_to_registered_domain(conn, settings):
    http = FakeHTTP({"https://rdap.org/domain/example.org": FakeResponse(200, rdap(4000))})
    r = make_enricher(conn, settings, http).run("deep.sub.example.org")
    assert r["rdap"]["domain"] == "example.org"
    assert r["verdict"] == "low"


def test_service_failures_are_reported_not_raised(conn, settings):
    http = FakeHTTP({"https://rdap.org/": FakeResponse(500, "oops")})
    r = make_enricher(conn, settings, http).run("8.8.8.8")
    assert "rdap" in r["errors"] and "ipinfo" in r["errors"]
    assert r["score"] == 0


def test_api_keys_only_used_when_set(conn, settings):
    http = FakeHTTP()
    make_enricher(conn, settings, http).run("8.8.8.8")
    urls = [u for _, u, _ in http.calls]
    assert not any("abuseipdb" in u or "virustotal" in u for u in urls)

    settings.abuseipdb_key, settings.virustotal_key = "a", "v"
    http = FakeHTTP({
        "https://api.abuseipdb.com/": FakeResponse(200, {"data": {"abuseConfidenceScore": 90, "totalReports": 12}}),
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8": FakeResponse(
            200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 4, "suspicious": 0}}}}),
    })
    r = make_enricher(conn, settings, http).run("8.8.8.8")
    assert r["abuseipdb"]["abuseConfidenceScore"] == 90
    assert r["virustotal"]["malicious"] == 4
    assert r["score"] == 90 and r["verdict"] == "malicious"


def test_virustotal_url_id_is_unpadded_base64(conn, settings):
    settings.virustotal_key = "v"
    http = FakeHTTP()
    make_enricher(conn, settings, http).run("http://a.example/")
    vt = [u for _, u, _ in http.calls if "virustotal" in u][0]
    assert vt.endswith("/urls/aHR0cDovL2EuZXhhbXBsZS8")


def test_active_checks_off_by_default(conn, settings):
    http = FakeHTTP()
    make_enricher(conn, settings, http).run("https://a.example/x")
    assert not any(u.startswith("https://a.example") for _, u, _ in http.calls)


def test_redirect_chain_followed_and_scored(conn, settings):
    http = FakeHTTP({
        "https://rdap.org/": FakeResponse(404, "{}"),
        "http://short.example/abc": FakeResponse(301, "", {"Location": "https://hop1.example/r"}),
        "https://hop1.example/r": FakeResponse(302, "", {"Location": "/r2"}),
        "https://hop1.example/r2": FakeResponse(302, "", {"Location": "https://landing.example/login"}),
        "https://landing.example/login": FakeResponse(200, "", {"Server": "nginx", "Content-Type": "text/html",
                                                                "X-Frame-Options": "DENY"}),
    })
    r = make_enricher(conn, settings, http).run("http://short.example/abc", active=True)
    h = r["http"]
    assert h["hops"] == 3 and h["final_url"] == "https://landing.example/login"
    assert h["chain"][1]["location"] == "https://hop1.example/r2"  # relative Location resolved
    assert h["cross_domain"] is True
    assert "x-frame-options" not in h["missing_security_headers"]
    assert "content-security-policy" in h["missing_security_headers"]
    assert "+10 3 redirects before landing" in r["reasons"]
    for _, url, kw in http.calls:
        if "example/" in url and "rdap" not in url:
            assert kw["allow_redirects"] is False


def test_ssrf_guard_blocks_private_targets(conn, settings):
    http = FakeHTTP({"http://intranet.example/": FakeResponse(200, "")})
    r = make_enricher(conn, settings, http, resolve=lambda h: ["192.168.1.10"]).run(
        "http://intranet.example/", active=True)
    assert "non-public address" in r["errors"]["http"]
    assert not any(u.startswith("http://intranet") for _, u, _ in http.calls)


def test_ssrf_guard_blocks_redirect_into_private_range(conn, settings):
    http = FakeHTTP({
        "https://rdap.org/": FakeResponse(404, "{}"),
        "http://public.example/": FakeResponse(302, "", {"Location": "http://127.0.0.1:8080/admin"}),
    })
    r = make_enricher(conn, settings, http).run("http://public.example/", active=True)
    assert "127.0.0.1" in r["errors"]["http"]
    assert not any("127.0.0.1" in u for _, u, _ in http.calls)


def _self_signed_der(cn, days_old):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = NOW - timedelta(days=days_old)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(start).not_valid_after(start + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def test_tls_certificate_parsed_and_scored(conn, settings):
    der = _self_signed_der("other.example", 2)
    http = FakeHTTP({"https://rdap.org/": FakeResponse(404, "{}"),
                     "https://phish.example/": FakeResponse(200, "")})
    r = make_enricher(conn, settings, http, tls_fetch=lambda h, p: (der, False, "self-signed")).run(
        "phish.example", active=True)
    t = r["tls"]
    assert t["subject_cn"] == "other.example" and t["self_signed"] is True
    assert t["hostname_match"] is False and t["age_days"] == 2
    assert {"+10 self-signed TLS certificate", "+15 TLS certificate doesn't match the hostname",
            "+10 TLS certificate issued 2 days ago"} <= set(r["reasons"])


@pytest.mark.parametrize("host,names,ok", [
    ("a.example.com", ["*.example.com"], True),
    ("a.b.example.com", ["*.example.com"], False),
    ("example.com", ["*.example.com"], False),
    ("Example.com", ["example.com"], True),
])
def test_wildcard_matching(host, names, ok):
    assert enrich._host_matches(host, names) is ok


def test_save_lookup_round_trip(conn, settings):
    r = make_enricher(conn, settings, FakeHTTP()).run("8.8.8.8")
    lookup_id = enrich.save_lookup(conn, r)
    row = conn.execute("SELECT * FROM lookups WHERE id=?", (lookup_id,)).fetchone()
    assert row["indicator"] == "8.8.8.8" and row["verdict"] == "low"


def test_hosted_url_on_shared_platform_is_weak_signal(conn, settings):
    feeds.store_indicators(conn, [{"value": "https://github.com/someone/repo/raw/main/x.exe", "type": "url",
                                   "host": "github.com", "source": "urlhaus", "threat": "malware_download"}])
    http = FakeHTTP({"https://rdap.org/domain/github.com": FakeResponse(200, rdap(6000))})
    r = make_enricher(conn, settings, http).run("github.com")
    assert r["feeds"]["exact"] == [] and r["feeds"]["hosted_total"] == 1
    assert r["score"] == 15 and r["verdict"] == "low"


def test_hosted_urls_on_bare_ip_weigh_more(conn, settings):
    feeds.store_indicators(conn, feeds.parse_urlhaus(fixture_text("urlhaus.csv")))
    r = make_enricher(conn, settings, FakeHTTP()).run("42.178.168.184")
    assert r["score"] == 40 and r["verdict"] == "suspicious"


def test_exact_url_hit(conn, settings):
    feeds.store_indicators(conn, feeds.parse_urlhaus(fixture_text("urlhaus.csv")))
    r = make_enricher(conn, settings, FakeHTTP()).run("http://42.178.168.184:38532/i")
    assert len(r["feeds"]["exact"]) == 1 and r["verdict"] == "malicious"


def test_private_ip_skips_lookups(conn, settings):
    http = FakeHTTP()
    r = make_enricher(conn, settings, http).run("10.1.2.3")
    assert http.calls == [] and r["errors"] == {}


@pytest.mark.parametrize("host,base", [
    ("www.wikipedia.org", "wikipedia.org"), ("a.b.example.co.uk", "example.co.uk"),
    ("example.com", "example.com"), ("8.8.8.8", "8.8.8.8")])
def test_base_domain(host, base):
    assert enrich.base_domain(host) == base
