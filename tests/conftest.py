import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURES = Path(__file__).parent / "fixtures"

from alpharius import db  # noqa: E402
from alpharius.config import Settings  # noqa: E402


class FakeResponse:
    def __init__(self, status=200, body="", headers=None):
        self.status_code = status
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.headers = headers or {}

    def json(self):
        return json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def close(self):
        pass


class FakeHTTP:
    """Routes by URL prefix. Records every call so tests can assert on them."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def _match(self, url):
        for prefix in sorted(self.routes, key=len, reverse=True):
            if url.startswith(prefix):
                r = self.routes[prefix]
                return r() if callable(r) else r
        return FakeResponse(404, "{}")

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self._match(url)

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self._match(url)


def fixture_text(name):
    return (FIXTURES / name).read_text()


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    yield c
    c.close()


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=str(tmp_path / "test.db"), secret_key="test", abusech_auth_key="",
                    ipinfo_token="", abuseipdb_key="", virustotal_key="", wazuh_url="https://indexer.test:9200",
                    wazuh_user="u", wazuh_password="p", wazuh_verify=False, http_timeout=5)
