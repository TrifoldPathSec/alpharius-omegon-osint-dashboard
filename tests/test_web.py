import re

import pytest
from conftest import FakeHTTP, FakeResponse, fixture_text

from alpharius import enrich, feeds
from alpharius.web import create_app


@pytest.fixture
def http():
    return FakeHTTP({
        feeds.URLHAUS_URL: FakeResponse(200, fixture_text("urlhaus.csv")),
        feeds.THREATFOX_URL: FakeResponse(200, fixture_text("threatfox.json")),
        feeds.FEODO_URL: FakeResponse(200, fixture_text("feodo.json")),
        feeds.KEV_URL: FakeResponse(200, fixture_text("kev.json")),
    })


@pytest.fixture
def client(settings, http):
    def factory(conn):
        return enrich.Enricher(conn, http, settings, resolve=lambda h: ["93.184.216.34"],
                               dns_query=lambda n, t: [])
    app = create_app(settings, http=http, enricher_factory=factory)
    app.testing = True
    return app.test_client()


def token(client, path="/"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def test_pages_render_empty(client):
    for path in ["/", "/indicators", "/enrich", "/lab", "/kev"]:
        resp = client.get(path)
        assert resp.status_code == 200, path
        assert "Content-Security-Policy" in resp.headers


def test_post_without_csrf_rejected(client):
    assert client.post("/ingest").status_code == 400
    assert client.post("/enrich", data={"value": "8.8.8.8", "csrf_token": "wrong"}).status_code == 400


def test_ingest_then_browse(client):
    resp = client.post("/ingest", data={"csrf_token": token(client)}, follow_redirects=True)
    html = resp.get_data(as_text=True)
    assert "4/4 feeds OK" in html
    assert 'id="chart-data"' in html
    html = client.get("/indicators?source=feodo").get_data(as_text=True)
    assert "162.243.103.246" in html and "42.178.168.184" not in html
    assert "Citrix Bleed" in client.get("/kev?q=citrix").get_data(as_text=True)


def test_enrich_flow_and_escaping(client):
    t = token(client, "/enrich")
    client.post("/ingest", data={"csrf_token": t})
    resp = client.post("/enrich", data={"value": "evil-c2[.]example", "csrf_token": t})
    assert resp.status_code == 302 and "/lookups/" in resp.headers["Location"]
    html = client.get(resp.headers["Location"]).get_data(as_text=True)
    assert "MALICIOUS" in html and "Remcos" in html

    bad = client.post("/enrich", data={"value": "<script>alert(1)</script>", "csrf_token": t},
                      follow_redirects=True).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in bad
    assert "Enter a single IP" in bad or "Not a recognisable" in bad


def test_unknown_lookup_404(client):
    assert client.get("/lookups/999").status_code == 404
