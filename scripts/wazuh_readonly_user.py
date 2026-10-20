"""Create a least-privilege Wazuh indexer user for alpharius-omegon.

Uses the OpenSearch security REST API with an admin account (prompted, never
stored) to create:
  role     alpharius_readonly   read on wazuh-alerts-* and wazuh-states-vulnerabilities-*
  user     alpharius            random password, written straight into .env
  mapping  alpharius -> alpharius_readonly

Then it checks the new user can read both index patterns and can't write.

    python scripts/wazuh_readonly_user.py            # reads URL / CA / server name from .env
"""
import getpass
import os
import secrets
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from alpharius.config import Settings  # noqa: E402
from alpharius.wazuh import indexer_session  # noqa: E402

USER = "alpharius"
ROLE = "alpharius_readonly"
INDICES = ["wazuh-alerts-*", "wazuh-states-vulnerabilities-*"]


def make_password(n: int = 28) -> str:
    """Meets the Wazuh indexer policy: upper, lower, digit and a symbol."""
    symbols = ".-*+?"
    pool = string.ascii_letters + string.digits + symbols
    while True:
        pw = "".join(secrets.choice(pool) for _ in range(n))
        if (any(c.isupper() for c in pw) and any(c.islower() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in symbols for c in pw)):
            return pw


def update_env(values: dict) -> None:
    path = ROOT / ".env"
    lines = path.read_text().splitlines() if path.exists() else []
    seen = set()
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip()
        if key in values:
            lines[i] = f"{key}={values[key]}"
            seen.add(key)
    lines += [f"{k}={v}" for k, v in values.items() if k not in seen]
    path.write_text("\n".join(lines) + "\n")
    os.chmod(path, 0o600)


def main() -> int:
    s = Settings.from_env()
    if not s.wazuh_url:
        sys.exit("Set WAZUH_INDEXER_URL in .env first.")
    if s.wazuh_verify is not True and s.wazuh_verify is not False and not Path(str(s.wazuh_verify)).is_file():
        sys.exit(f"CA file not found: {s.wazuh_verify}")
    http = indexer_session(s)
    base = f"{s.wazuh_url}/_plugins/_security/api"

    admin = input("Indexer admin user [admin]: ").strip() or "admin"
    admin_pw = getpass.getpass(f"Password for {admin} (not shown, not saved): ")
    auth = (admin, admin_pw)

    def call(method, path, body=None):
        r = http.request(method, f"{base}/{path}", json=body, auth=auth, verify=s.wazuh_verify, timeout=30)
        if r.status_code == 401:
            sys.exit("Admin login failed (401). Check the admin username/password.")
        if r.status_code >= 400:
            sys.exit(f"{method} {path} failed: HTTP {r.status_code} {r.text[:300]}")
        return r

    call("PUT", f"roles/{ROLE}", {
        "description": "alpharius-omegon: read alerts and vulnerability states",
        "cluster_permissions": ["cluster_composite_ops_ro"],
        "index_permissions": [{"index_patterns": INDICES, "allowed_actions": ["read"]}],
    })
    print(f"role {ROLE}: ok")

    password = make_password()
    call("PUT", f"internalusers/{USER}", {
        "password": password,
        "description": "alpharius-omegon read-only threat-intel matcher",
    })
    print(f"user {USER}: ok")

    call("PUT", f"rolesmapping/{ROLE}", {"users": [USER]})
    print(f"mapping {USER} -> {ROLE}: ok")

    update_env({"WAZUH_INDEXER_USER": USER, "WAZUH_INDEXER_PASSWORD": password})
    print(".env updated (chmod 600); the password was not printed")

    # Verify least privilege with the new account
    new_auth = (USER, password)
    for index in INDICES:
        r = http.get(f"{s.wazuh_url}/{index}/_count", auth=new_auth, verify=s.wazuh_verify, timeout=30)
        detail = r.json().get("count") if r.ok else r.text[:120]
        print(f"read  {index:34} HTTP {r.status_code}  count={detail}")
    r = http.post(f"{s.wazuh_url}/wazuh-alerts-alpharius-write-test/_doc", json={"x": 1},
                  auth=new_auth, verify=s.wazuh_verify, timeout=30)
    print(f"write test (should be 403)               HTTP {r.status_code}")
    return 0 if r.status_code == 403 else 1


if __name__ == "__main__":
    sys.exit(main())
