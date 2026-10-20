"""Settings, read from environment variables and an optional .env file."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
USER_AGENT = "alpharius-omegon/1.0 (defensive threat-intel lab)"


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Minimal .env loader: KEY=value lines, '#' comments. Real env vars win."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass
class Settings:
    db_path: str
    secret_key: str
    abusech_auth_key: str
    ipinfo_token: str
    abuseipdb_key: str
    virustotal_key: str
    wazuh_url: str
    wazuh_user: str
    wazuh_password: str
    wazuh_verify: object  # True, False, or a CA bundle path
    http_timeout: float = 20.0

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        env = os.environ.get
        verify_raw = env("WAZUH_INDEXER_VERIFY", "true")
        if verify_raw.lower() in ("false", "0", "no"):
            verify: object = False
        elif verify_raw.lower() in ("true", "1", "yes", ""):
            verify = True
        else:
            verify = verify_raw
        return cls(
            db_path=env("ALPHARIUS_DB", str(ROOT / "data" / "alpharius.db")),
            secret_key=env("FLASK_SECRET_KEY", "") or os.urandom(32).hex(),
            abusech_auth_key=env("ABUSECH_AUTH_KEY", ""),
            ipinfo_token=env("IPINFO_TOKEN", ""),
            abuseipdb_key=env("ABUSEIPDB_API_KEY", ""),
            virustotal_key=env("VIRUSTOTAL_API_KEY", ""),
            wazuh_url=env("WAZUH_INDEXER_URL", "").rstrip("/"),
            wazuh_user=env("WAZUH_INDEXER_USER", ""),
            wazuh_password=env("WAZUH_INDEXER_PASSWORD", ""),
            wazuh_verify=verify,
        )
