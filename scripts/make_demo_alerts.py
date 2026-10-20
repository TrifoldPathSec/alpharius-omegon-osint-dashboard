"""Write samples/demo-alerts.jsonl: synthetic Wazuh-style alerts for a demo.

A few alerts reference real indicators from your freshly ingested feeds (so the
Lab matches page has something to show); the rest are benign lab noise with
private addresses. Nothing here comes from a real lab.

    python scripts/make_demo_alerts.py && python -m alpharius match-alerts --file samples/demo-alerts.jsonl
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from alpharius import db  # noqa: E402
from alpharius.config import Settings  # noqa: E402


def main() -> None:
    conn = db.connect(Settings.from_env().db_path)
    pick = lambda sql: conn.execute(sql).fetchone()  # noqa: E731
    c2 = pick("SELECT value FROM indicators WHERE source='feodo' ORDER BY last_seen DESC LIMIT 1")
    tf_ip = pick("SELECT value FROM indicators WHERE source='threatfox' AND type='ip' ORDER BY first_seen DESC LIMIT 1")
    tf_dom = pick("SELECT value FROM indicators WHERE source='threatfox' AND type='domain' ORDER BY first_seen DESC LIMIT 1")
    url = pick("SELECT value FROM indicators WHERE source='urlhaus' ORDER BY first_seen DESC LIMIT 1")
    if not all([c2, tf_ip, tf_dom, url]):
        sys.exit("Run `python -m alpharius ingest` first.")

    now = datetime.now(timezone.utc)
    ts = lambda h: (now - timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")  # noqa: E731
    alerts = [
        {"id": "demo-1", "timestamp": ts(30), "rule": {"id": "100210", "description": "Outbound connection to rare destination"},
         "agent": {"name": "lab-macbook"}, "data": {"srcip": "10.10.10.21", "dstip": c2[0], "dstport": "443"}},
        {"id": "demo-2", "timestamp": ts(20), "rule": {"id": "100211", "description": "DNS query logged"},
         "agent": {"name": "lab-macbook"}, "data": {"dns": {"queryname": tf_dom[0]}}},
        {"id": "demo-3", "timestamp": ts(6), "rule": {"id": "31108", "description": "Web request from curl"},
         "agent": {"name": "lab-ubuntu-vm"}, "data": {"url": url[0]}},
        {"id": "demo-4", "timestamp": ts(2), "rule": {"id": "100210", "description": "Outbound connection to rare destination"},
         "agent": {"name": "lab-ubuntu-vm"}, "data": {"srcip": "10.10.10.30", "dstip": tf_ip[0]}},
        {"id": "demo-5", "timestamp": ts(1), "rule": {"id": "5715", "description": "sshd: authentication success"},
         "agent": {"name": "lab-ubuntu-vm"}, "data": {"srcip": "10.10.10.21"}, "full_log": "Accepted password from 10.10.10.21"},
    ]
    out = ROOT / "samples" / "demo-alerts.jsonl"
    out.write_text("".join(json.dumps(a) + "\n" for a in alerts))
    print(f"wrote {len(alerts)} alerts to {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
