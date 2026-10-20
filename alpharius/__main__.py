"""Command line: python -m alpharius <command>"""
from __future__ import annotations

import argparse
import json
import sys

from . import db, enrich, feeds, wazuh
from .config import Settings
from .web import create_app, http_session


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="alpharius", description="Open-source threat intelligence dashboard")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("ingest", help="pull the public threat feeds into SQLite")
    sp.add_argument("--source", action="append", choices=list(feeds.FEEDS),
                    help="only this feed (repeatable); default is all")

    sp = sub.add_parser("enrich", help="enrich one IP, domain, URL or hash")
    sp.add_argument("value")
    sp.add_argument("--active", action="store_true",
                    help="also follow redirects and pull the TLS certificate (contacts the host)")
    sp.add_argument("--json", action="store_true", help="print the full result as JSON")

    for name, what in (("match-alerts", "Wazuh alerts"), ("match-vulns", "Wazuh vulnerability findings")):
        sp = sub.add_parser(name, help=f"match {what} against the intel")
        src = sp.add_mutually_exclusive_group(required=True)
        src.add_argument("--file", help="alerts.json lines, JSON array or saved indexer response")
        src.add_argument("--indexer", action="store_true", help="query the Wazuh indexer (see .env)")
        if name == "match-alerts":
            sp.add_argument("--hours", type=int, default=24, help="look-back window for --indexer")

    sp = sub.add_parser("serve", help="run the dashboard on localhost")
    sp.add_argument("--port", type=int, default=5001)

    args = p.parse_args(argv)
    settings = Settings.from_env()

    if args.cmd == "serve":
        # Bound to loopback on purpose: this is a single-analyst lab tool with no login.
        create_app(settings).run(host="127.0.0.1", port=args.port, debug=False)
        return 0

    conn = db.connect(settings.db_path)
    http = http_session()

    if args.cmd == "ingest":
        results = feeds.ingest(conn, http, args.source, settings.abusech_auth_key, log=print)
        return 0 if all(r["status"] == "ok" for r in results) else 1

    if args.cmd == "enrich":
        try:
            result = enrich.Enricher(conn, http, settings).run(args.value, active=args.active)
        except enrich.EnrichError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        lookup_id = enrich.save_lookup(conn, result)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(f"{result['indicator']} ({result['type']}): {result['verdict'].upper()} "
                  f"score {result['score']}/100  [lookup #{lookup_id}]")
            for reason in result["reasons"]:
                print(f"  {reason}")
            for section, err in result["errors"].items():
                print(f"  ! {section}: {err}")
        return 0

    if args.cmd == "match-alerts":
        docs = wazuh.load_docs(args.file) if args.file else \
            wazuh.fetch_alerts(wazuh.indexer_session(settings, http), settings, args.hours)
        print(wazuh.match_alerts(conn, docs))
        return 0

    if args.cmd == "match-vulns":
        docs = wazuh.load_docs(args.file) if args.file else \
            wazuh.fetch_vulns(wazuh.indexer_session(settings, http), settings)
        print(wazuh.match_vulns(conn, docs))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
