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
