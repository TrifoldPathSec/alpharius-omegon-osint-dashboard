"""Flask dashboard."""
from __future__ import annotations

import json
import secrets
from typing import Optional

import requests
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)

from . import db, enrich, feeds
from .config import USER_AGENT, Settings

PAGE_SIZE = 50


def http_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def create_app(settings: Optional[Settings] = None, http=None, enricher_factory=None) -> Flask:
    settings = settings or Settings.from_env()
    app = Flask(__name__)
    app.config.update(SECRET_KEY=settings.secret_key, SESSION_COOKIE_SAMESITE="Strict",
                      SESSION_COOKIE_HTTPONLY=True)
    app.extensions["alpharius"] = settings
    http = http or http_session()

    def get_db():
        if "db" not in g:
            g.db = db.connect(settings.db_path)
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    # ---- CSRF: one token per session, required on every POST ----
    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def check_csrf():
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                abort(400, "CSRF token missing or invalid")

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        return resp

    acronyms = {"ip": "IP", "cn": "CN", "sans": "SANs", "dns": "DNS", "tls": "TLS", "url": "URL"}

    @app.template_filter("label")
    def label(key: str) -> str:
        words = [acronyms.get(w, w) for w in str(key).split("_")]
        return " ".join(words)[:1].upper() + " ".join(words)[1:]

    # ---- pages ----

    @app.route("/")
    def overview():
        conn = get_db()
        charts = {
            "daily": db.daily_new_by_source(conn),
            "malware": db.top_malware(conn),
            "countries": db.c2_countries(conn),
            "types": db.type_breakdown(conn),
            "kev": db.kev_by_month(conn),
            "matches": db.matches_by_day(conn),
        }
        return render_template("overview.html", counts=db.overview_counts(conn), charts=charts,
                               runs=db.recent_runs(conn))

    @app.post("/ingest")
    def run_ingest():
        results = feeds.ingest(get_db(), http, abusech_key=settings.abusech_auth_key)
        ok = [r for r in results if r["status"] == "ok"]
        flash(f"Ingest finished: {len(ok)}/{len(results)} feeds OK, "
              f"{sum(r.get('new', 0) for r in ok)} new records.",
              "ok" if len(ok) == len(results) else "warn")
        return redirect(url_for("overview"))

    @app.route("/indicators")
    def indicators():
        conn = get_db()
        q = request.args.get("q", "").strip()
        source = request.args.get("source", "")
        kind = request.args.get("type", "")
        page = max(1, request.args.get("page", 1, type=int))
        where, args = [], []
        if q:
            where.append("(value LIKE ? OR malware LIKE ? OR tags LIKE ?)")
            args += [f"%{q}%"] * 3
        if source in feeds.FEEDS:
            where.append("source = ?")
            args.append(source)
        if kind in ("ip", "domain", "url", "hash"):
            where.append("type = ?")
            args.append(kind)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        total = conn.execute(f"SELECT COUNT(*) FROM indicators {clause}", args).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM indicators {clause} ORDER BY first_seen DESC LIMIT ? OFFSET ?",
            args + [PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
        return render_template("indicators.html", rows=rows, total=total, page=page,
                               pages=max(1, -(-total // PAGE_SIZE)), q=q, source=source, kind=kind)

    @app.route("/enrich", methods=["GET", "POST"])
    def enrich_view():
        if request.method == "GET":
            recent = get_db().execute(
                "SELECT id, indicator, type, score, verdict, created_at FROM lookups ORDER BY id DESC LIMIT 25"
            ).fetchall()
            return render_template("enrich.html", recent=recent, value=request.args.get("value", ""))
        value = request.form.get("value", "")
        active = request.form.get("active") == "on"
        factory = enricher_factory or (lambda conn: enrich.Enricher(conn, http, settings))
        try:
            result = factory(get_db()).run(value, active=active)
        except enrich.EnrichError as exc:
            flash(str(exc), "warn")
            return redirect(url_for("enrich_view", value=value))
        lookup_id = enrich.save_lookup(get_db(), result)
        return redirect(url_for("lookup_view", lookup_id=lookup_id))

    @app.route("/lookups/<int:lookup_id>")
    def lookup_view(lookup_id: int):
        row = get_db().execute("SELECT * FROM lookups WHERE id=?", (lookup_id,)).fetchone()
        if not row:
            abort(404)
        return render_template("lookup.html", row=row, r=json.loads(row["result_json"]))

    @app.route("/lab")
    def lab():
        conn = get_db()
        alerts = conn.execute("SELECT * FROM alert_matches ORDER BY alert_time DESC LIMIT 200").fetchall()
        vulns = conn.execute(
            """SELECT v.*, k.vendor, k.product, k.name AS kev_name FROM vuln_matches v
               LEFT JOIN kev k ON k.cve_id = v.cve_id
               ORDER BY (v.ransomware='Known') DESC, v.due_date ASC LIMIT 200""").fetchall()
        return render_template("lab.html", alerts=alerts, vulns=vulns)

    @app.route("/kev")
    def kev():
        q = request.args.get("q", "").strip()
        args, clause = [], ""
        if q:
            clause = "WHERE cve_id LIKE ? OR vendor LIKE ? OR product LIKE ? OR name LIKE ?"
            args = [f"%{q}%"] * 4
        rows = get_db().execute(
            f"SELECT * FROM kev {clause} ORDER BY date_added DESC LIMIT 200", args).fetchall()
        return render_template("kev.html", rows=rows, q=q)

    return app
