"""Flask report server.

Routes:
    /                       dashboard (summary, severity breakdown, resolved)
    /devices                by-device table
    /device/<id>            device drill-down (services, findings, firmware)
    /vulnerabilities        by-vulnerability table (grouped by CVE)
    /vuln/<cve_id>          CVE drill-down (affected devices, remediation)
    /scans                  scan history

Read-only over the SQLite DB produced by a scan. Bind to 127.0.0.1 by default.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import Flask, abort, render_template, request

from ..db import Database


def _fmt_ts(value):
    if not value:
        return "—"
    return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def create_app(db_path: str) -> Flask:
    app = Flask(__name__)
    app.jinja_env.filters["ts"] = _fmt_ts
    app.jinja_env.filters["fromjson"] = lambda s: json.loads(s) if s else []
    app.jinja_env.filters["pct"] = lambda v: f"{(v or 0)*100:.1f}%"

    def get_db() -> Database:
        return Database(db_path)

    def _resolve_scan(db: Database) -> int | None:
        sid = request.args.get("scan", type=int)
        return sid if sid else db.latest_scan_id()

    @app.route("/")
    def dashboard():
        db = get_db()
        scan_id = _resolve_scan(db)
        if scan_id is None:
            return render_template("empty.html")
        summary = db.summary(scan_id)
        scan = db.scan(scan_id)
        top_hosts = db.hosts(scan_id)[:8]
        top_cves = db.findings_grouped_by_cve(scan_id)[:8]
        resolved = db.resolved_for_scan(scan_id)
        scans = db.all_scans()
        db.close()
        return render_template("dashboard.html", summary=summary, scan=scan,
                               top_hosts=top_hosts, top_cves=top_cves,
                               resolved=resolved, scans=scans, scan_id=scan_id)

    @app.route("/devices")
    def devices():
        db = get_db()
        scan_id = _resolve_scan(db)
        if scan_id is None:
            return render_template("empty.html")
        hosts = db.hosts(scan_id)
        # attach finding counts per host
        for h in hosts:
            fs = db.findings_for_host(h["id"])
            h["finding_count"] = len(fs)
            h["kev_count"] = sum(1 for f in fs if f["is_kev"])
        scans = db.all_scans()
        db.close()
        return render_template("devices.html", hosts=hosts, scan_id=scan_id, scans=scans)

    @app.route("/device/<int:host_id>")
    def device_detail(host_id: int):
        db = get_db()
        host = db.host(host_id)
        if not host:
            db.close()
            abort(404)
        services = db.services(host_id)
        firmware = next((s for s in db.info_services(host_id)
                         if s["service"] == "firmware-advice"), None)
        software = db.software(host_id)
        facts = db.facts(host_id)
        findings = db.findings_for_host(host_id)
        db.close()
        return render_template("device_detail.html", host=host, services=services,
                               findings=findings, firmware=firmware,
                               software=software, facts=facts)

    @app.route("/vulnerabilities")
    def vulnerabilities():
        db = get_db()
        scan_id = _resolve_scan(db)
        if scan_id is None:
            return render_template("empty.html")
        cves = db.findings_grouped_by_cve(scan_id)
        scans = db.all_scans()
        db.close()
        return render_template("vulnerabilities.html", cves=cves,
                               scan_id=scan_id, scans=scans)

    @app.route("/vuln/<cve_id>")
    def vuln_detail(cve_id: str):
        db = get_db()
        scan_id = _resolve_scan(db)
        if scan_id is None:
            db.close()
            abort(404)
        rows = db.finding_by_cve(scan_id, cve_id)
        if not rows:
            db.close()
            abort(404)
        db.close()
        return render_template("vuln_detail.html", cve_id=cve_id, rows=rows,
                               first=rows[0])

    @app.route("/weaknesses")
    def weaknesses():
        db = get_db()
        scan_id = _resolve_scan(db)
        if scan_id is None:
            return render_template("empty.html")
        owasp = db.findings_grouped_by_owasp(scan_id)
        cwe = db.findings_grouped_by_cwe(scan_id)
        scans = db.all_scans()
        db.close()
        return render_template("weaknesses.html", owasp=owasp, cwe=cwe,
                               scan_id=scan_id, scans=scans)

    @app.route("/scans")
    def scans():
        db = get_db()
        all_scans = db.all_scans()
        db.close()
        return render_template("scans.html", scans=all_scans)

    return app
