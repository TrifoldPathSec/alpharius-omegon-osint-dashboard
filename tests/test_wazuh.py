import json

from conftest import FIXTURES, FakeHTTP, FakeResponse, fixture_text

from alpharius import feeds, wazuh


def load_intel(conn):
    feeds.store_indicators(conn, feeds.parse_urlhaus(fixture_text("urlhaus.csv")))
    feeds.store_indicators(conn, feeds.parse_threatfox(fixture_text("threatfox.json")))
    feeds.store_indicators(conn, feeds.parse_feodo(fixture_text("feodo.json")))
    feeds.store_kev(conn, feeds.parse_kev(fixture_text("kev.json")))


def test_load_docs_formats(tmp_path):
    assert len(wazuh.load_docs(str(FIXTURES / "alerts.jsonl"))) == 4  # bad line skipped
    assert len(wazuh.load_docs(str(FIXTURES / "vulns.json"))) == 3   # indexer response
    arr = tmp_path / "a.json"
    arr.write_text('[{"_source": {"id": "x"}}, {"id": "y"}]')
    assert [d["id"] for d in wazuh.load_docs(str(arr))] == ["x", "y"]


def test_extract_observables_skips_private_ips():
    obs = wazuh.extract_observables({
        "data": {"srcip": "10.0.0.15", "dstip": "206.123.152.197", "dns": {"queryname": "evil-c2.example"},
                 "msg": "GET http://bad.example/x.sh, then 8.8.8.8"},
        "full_log": "from 192.168.1.1 to 1.1.1.1"})
    values = {v for _, v in obs}
    assert {"206.123.152.197", "evil-c2.example", "http://bad.example/x.sh", "bad.example",
            "8.8.8.8", "1.1.1.1"} <= values
    assert "10.0.0.15" not in values and "192.168.1.1" not in values


def test_match_alerts(conn):
    load_intel(conn)
    res = wazuh.match_alerts(conn, wazuh.load_docs(str(FIXTURES / "alerts.jsonl")))
    assert res["alerts_scanned"] == 4
    rows = {(r["alert_id"], r["value"], r["source"]) for r in conn.execute("SELECT * FROM alert_matches")}
    assert ("1001", "206.123.152.197", "threatfox") in rows
    assert ("1002", "evil-c2.example", "threatfox") in rows
    assert ("1003", "http://42.178.168.184:38532/i", "urlhaus") in rows
    assert not any(a == "1004" for a, _, _ in rows)  # private-only alert
    # Re-running doesn't duplicate
    again = wazuh.match_alerts(conn, wazuh.load_docs(str(FIXTURES / "alerts.jsonl")))
    assert again["new_matches"] == 0


def test_match_vulns_against_kev(conn):
    load_intel(conn)
    res = wazuh.match_vulns(conn, wazuh.load_docs(str(FIXTURES / "vulns.json")))
    assert res == {"vulns_scanned": 3, "new_matches": 2}
    rows = {r["cve_id"]: dict(r) for r in conn.execute("SELECT * FROM vuln_matches")}
    assert rows["CVE-2024-3094"]["package"] == "liblzma5"
    assert rows["CVE-2023-4966"]["ransomware"] == "Known"  # legacy alert format, lower-case CVE


def test_indexer_query_uses_auth_and_verify(settings):
    http = FakeHTTP({"https://indexer.test:9200/wazuh-alerts-*/_search":
                     FakeResponse(200, {"hits": {"hits": [{"_source": {"id": "1"}}]}})})
    docs = wazuh.fetch_alerts(http, settings, hours=6)
    assert docs == [{"id": "1"}]
    _, _, kw = http.calls[0]
    assert kw["auth"] == ("u", "p") and kw["verify"] is False
    assert kw["json"]["query"]["range"]["timestamp"]["gte"] == "now-6h"


def test_domain_of_hosted_url_does_not_match(conn):
    feeds.store_indicators(conn, [{"value": "https://github.com/x/y/raw/z.exe", "type": "url",
                                   "host": "github.com", "source": "urlhaus"}])
    alert = {"id": "g1", "data": {"dns": {"queryname": "github.com"}}}
    assert wazuh.match_alerts(conn, [alert])["new_matches"] == 0


def test_indexer_session_pins_server_name(settings):
    settings.wazuh_server_name = "wazuh.indexer"
    session = wazuh.indexer_session(settings)
    adapter = session.get_adapter(f"{settings.wazuh_url}/wazuh-alerts-*/_search")
    assert isinstance(adapter, wazuh.ServerNameAdapter)
    assert adapter.poolmanager.connection_pool_kw["assert_hostname"] == "wazuh.indexer"
    assert adapter.poolmanager.connection_pool_kw["server_hostname"] == "wazuh.indexer"
    ctx = adapter.poolmanager.connection_pool_kw["ssl_context"]
    import ssl
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.get_ca_certs() == []  # only the lab CA gets loaded
    # other hosts keep the normal adapter
    assert not isinstance(session.get_adapter("https://rdap.org/"), wazuh.ServerNameAdapter)


def test_indexer_requires_credentials(settings):
    import pytest
    settings.wazuh_password = ""
    with pytest.raises(RuntimeError, match="wazuh_readonly_user"):
        wazuh.fetch_alerts(FakeHTTP(), settings)


def test_config_assessment_alerts_are_skipped():
    sca = {"rule": {"groups": ["sca"]}, "data": {"sca": {"check": {"references": "https://evil-c2.example/x"}}}}
    assert wazuh.extract_observables(sca) == set()
    doc = {"rule": {"groups": ["web"]}, "data": {"description": "see https://docs.example/x", "url": "http://1.1.1.1/a"}}
    values = {v for _, v in wazuh.extract_observables(doc)}
    assert "https://docs.example/x" not in values and "http://1.1.1.1/a" in values


# IPv6: public resolver addresses stand in for "public" (2001:db8::/32 is the
# documentation prefix and is deliberately not global, so it must be dropped).
CF6 = "2606:4700:4700::1111"
GOOG6 = "2001:4860:4860::8888"


def test_extract_ipv6_from_ip_fields_only():
    obs = wazuh.extract_observables({
        "rule": {"groups": ["netwatch"]},
        "data": {"srcip": "2001:db8:482:3000::c61e",            # documentation, not global
                 "dstip": "2606:4700:4700:0000:0000:0000:0000:1111",  # expanded form
                 "dns": {"queryname": "example.com", "answers": [GOOG6, "fe80::1%en0", "93.184.215.14"]},
                 "msg": f"freeform text mentioning {CF6} is ignored"},
        "full_log": f"{GOOG6} in full_log is ignored"})
    assert ("data.dstip", CF6) in obs
    assert ("data.dns.answers", GOOG6) in obs
    values = {v for _, v in obs}
    assert "2001:db8:482:3000::c61e" not in values and "fe80::1" not in values
    assert not any(f in ("data.msg", "full_log") and ":" in v for f, v in obs)


def test_ipv6_list_string_and_rrname():
    obs = wazuh.extract_observables({"data": {"answers": f"[{CF6}], {GOOG6}",
                                              "dns": {"rrname": "Evil-C2.example."}}})
    assert {("data.answers", CF6), ("data.answers", GOOG6),
            ("data.dns.rrname", "evil-c2.example")} <= obs


def test_ipv6_url_host_is_compressed():
    obs = wazuh.extract_observables({"data": {"url": "http://[2606:4700:4700:0:0:0:0:1111]/x.sh"}})
    assert ("data.url", CF6) in obs


def test_threatfox_ipv6_ip_port():
    text = json.dumps({"1": [{"ioc_type": "ip:port", "ioc_value": "[2606:4700:4700:0::1111]:443"}],
                       "2": [{"ioc_type": "ip:port", "ioc_value": "203.0.113.9:8080"}]})
    rows = {r["value"]: r["host"] for r in feeds.parse_threatfox(text)}
    assert rows == {CF6: CF6, "203.0.113.9": "203.0.113.9"}


def test_match_alerts_ipv6_exact_and_host(conn):
    feeds.store_indicators(conn, [
        {"value": CF6, "type": "ip", "host": CF6, "source": "threatfox"},
        {"value": f"http://[{GOOG6}]:8080/payload", "type": "url",
         "host": feeds.url_host(f"http://[{GOOG6}]:8080/payload"), "source": "urlhaus"}])
    alerts = [{"id": "v6a", "rule": {"groups": ["netwatch"]}, "data": {"dstip": CF6}},
              {"id": "v6b", "rule": {"groups": ["netwatch"]}, "data": {"dns": {"answers": [GOOG6]}}},
              {"id": "v6c", "data": {"dstip": "2001:db8::1"}}]
    assert wazuh.match_alerts(conn, alerts)["new_matches"] == 2
    rows = {(r["alert_id"], r["value"], r["source"]) for r in conn.execute("SELECT * FROM alert_matches")}
    assert rows == {("v6a", CF6, "threatfox"), ("v6b", GOOG6, "urlhaus")}
