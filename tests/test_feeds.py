from conftest import FakeHTTP, FakeResponse, fixture_text

from alpharius import db, feeds


def test_parse_urlhaus_skips_comments_and_extracts_host():
    rows = feeds.parse_urlhaus(fixture_text("urlhaus.csv"))
    assert len(rows) == 2
    assert rows[0]["host"] == "42.178.168.184"
    assert rows[0]["tags"] == "32-bit,elf,mips,Mozi"
    assert rows[1]["host"] == "login-update.badcdn.example"
    assert rows[1]["tags"] is None  # "None" string normalised


def test_parse_threatfox_maps_types_and_strips_ports():
    rows = feeds.parse_threatfox(fixture_text("threatfox.json"))
    by_type = {r["type"]: r for r in rows}
    assert set(by_type) == {"ip", "hash", "domain"}  # unknown type dropped
    assert by_type["ip"]["value"] == "206.123.152.197"
    assert by_type["ip"]["malware"] == "Remcos"
    assert by_type["hash"]["host"] is None


def test_parse_feodo_and_kev():
    feodo = feeds.parse_feodo(fixture_text("feodo.json"))
    assert feodo[1]["status"] == "online" and feodo[1]["country"] == "US"
    assert "port:443" in feodo[1]["tags"]
    kev = feeds.parse_kev(fixture_text("kev.json"))
    assert {k["cve_id"] for k in kev} == {"CVE-2024-3094", "CVE-2023-4966"}


def test_store_is_idempotent_and_counts_new(conn):
    rows = feeds.parse_feodo(fixture_text("feodo.json"))
    assert feeds.store_indicators(conn, rows) == 2
    rows[0]["status"] = "online"
    assert feeds.store_indicators(conn, rows) == 0
    status = conn.execute("SELECT status FROM indicators WHERE value='162.243.103.246'").fetchone()[0]
    assert status == "online"  # upsert updated the existing row


def full_feed_http():
    return FakeHTTP({
        feeds.URLHAUS_URL: FakeResponse(200, fixture_text("urlhaus.csv")),
        feeds.THREATFOX_URL: FakeResponse(200, fixture_text("threatfox.json")),
        feeds.FEODO_URL: FakeResponse(200, fixture_text("feodo.json")),
        feeds.KEV_URL: FakeResponse(200, fixture_text("kev.json")),
    })


def test_ingest_all_feeds_logs_runs(conn):
    results = feeds.ingest(conn, full_feed_http())
    assert [r["status"] for r in results] == ["ok"] * 4
    counts = db.overview_counts(conn)
    assert counts["indicators"] == 7
    assert counts["kev"] == 2 and counts["kev_ransomware"] == 1
    assert counts["online_c2"] == 1
    assert len(db.recent_runs(conn)) == 4


def test_one_failing_feed_does_not_stop_others(conn):
    http = full_feed_http()
    http.routes[feeds.THREATFOX_URL] = FakeResponse(503, "busy")
    results = feeds.ingest(conn, http)
    status = {r["source"]: r["status"] for r in results}
    assert status["threatfox"] == "error"
    assert status["feodo"] == "ok"
    err = conn.execute("SELECT error FROM ingest_runs WHERE source='threatfox'").fetchone()[0]
    assert "503" in err


def test_abusech_key_sent_only_to_abusech(conn):
    http = full_feed_http()
    feeds.ingest(conn, http, abusech_key="k123")
    for _method, url, kw in http.calls:
        has_key = "Auth-Key" in kw.get("headers", {})
        assert has_key == ("abuse.ch" in url)


def test_chart_queries_shape(conn):
    feeds.ingest(conn, full_feed_http())
    malware = {r["label"] for r in db.top_malware(conn)}
    assert {"Remcos", "Emotet", "QakBot"} <= malware
    assert db.c2_countries(conn) == [{"label": "US", "n": 2}]
    types = {r["label"]: r["n"] for r in db.type_breakdown(conn)}
    assert types == {"ip": 3, "url": 2, "hash": 1, "domain": 1}
