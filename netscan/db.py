"""SQLite persistence.

Schema is built around being able to answer two questions the report needs:

  1. "What is vulnerable right now?"  -> latest scan's findings
  2. "Did the thing we patched actually get fixed?" -> compare a finding's
     presence between consecutive scans.

A *finding* is uniquely identified across scans by
(host_key, cve_id, port). host_key is the MAC address when we have it
(stable across DHCP lease changes) otherwise the IP. When a finding that was
present in the previous scan is absent in the current scan, we mark it
RESOLVED. If still present, PERSISTING. If brand new, NEW.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   REAL NOT NULL,
    finished_at  REAL,
    profile      TEXT,
    targets      TEXT,
    host_count   INTEGER DEFAULT 0,  -- hosts that responded (== succeeded)
    hosts_attempted INTEGER,         -- targets expanded minus excludes; NULL if not derivable
    hosts_failed    INTEGER,         -- max(0, hosts_attempted - host_count)
    finding_count INTEGER DEFAULT 0,
    status       TEXT DEFAULT 'SUCCESS', -- RUNNING | SUCCESS | FAILED
    error        TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    host_key    TEXT NOT NULL,        -- MAC if known else IP
    ip          TEXT NOT NULL,
    mac         TEXT,
    hostname    TEXT,
    vendor      TEXT,                 -- MAC OUI vendor
    os_name     TEXT,
    os_accuracy INTEGER,
    os_build    TEXT,                 -- precise build/version (credentialed)
    device_type TEXT,                 -- e.g. router/switch/general purpose
    auth_method TEXT DEFAULT 'network', -- network | ssh | winrm
    risk_score  REAL DEFAULT 0,
    vt_malicious INTEGER DEFAULT 0,   -- VT detections against the host IP
    UNIQUE(scan_id, host_key)
);

CREATE TABLE IF NOT EXISTS services (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id   INTEGER NOT NULL REFERENCES hosts(id),
    port      INTEGER NOT NULL,
    proto     TEXT,
    state     TEXT,
    service   TEXT,
    product   TEXT,
    version   TEXT,
    cpe       TEXT,
    source    TEXT DEFAULT 'network'  -- network | ssh | winrm
);

-- Free-form per-host facts gathered by credentialed scanning (installed
-- hotfix/KB ids, kernel version, package counts, ...).
CREATE TABLE IF NOT EXISTS host_facts (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    key     TEXT NOT NULL,
    value   TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    host_id     INTEGER NOT NULL REFERENCES hosts(id),
    host_key    TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    port        INTEGER,
    service     TEXT,
    product     TEXT,
    version     TEXT,
    cpe         TEXT,
    cvss        REAL,
    severity    TEXT,
    is_kev      INTEGER DEFAULT 0,
    ransomware  INTEGER DEFAULT 0,    -- KEV: known ransomware campaign use
    epss        REAL DEFAULT 0,       -- exploit probability (0..1)
    epss_pct    REAL DEFAULT 0,       -- EPSS percentile
    cwe         TEXT,                 -- primary CWE id e.g. CWE-79
    cwe_name    TEXT,
    owasp_key   TEXT,                 -- OWASP 2025 family key
    owasp_name  TEXT,
    priority    REAL DEFAULT 0,       -- blended urgency score
    summary     TEXT,
    remediation TEXT,                 -- JSON list of steps
    refs        TEXT,                 -- JSON list of reference URLs
    source      TEXT DEFAULT 'network', -- network | ssh | winrm | oval | msrc
    status      TEXT DEFAULT 'NEW'    -- NEW | PERSISTING
);

-- Findings that were present last scan but gone this scan.
CREATE TABLE IF NOT EXISTS resolved_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),  -- the scan in which it was found gone
    host_key    TEXT NOT NULL,
    ip          TEXT,
    cve_id      TEXT NOT NULL,
    port        INTEGER,
    severity    TEXT,
    is_kev      INTEGER DEFAULT 0,
    resolved_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve  ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_hosts_scan    ON hosts(scan_id);

-- Per-(host, cve, port) lineage across scans: when it was first/last seen,
-- when it was resolved (if ever), and whether it came back after resolution.
-- Populated by mark_lifecycle_seen()/mark_lifecycle_resolved() (called from
-- correlate.run_scan and demo.seed) and read by lifecycle_trend(), which
-- backs the Opened/Closed/Recurring counts on the /scans view.
CREATE TABLE IF NOT EXISTS finding_lifecycle (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_key    TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    port        INTEGER,
    first_seen  REAL,
    last_seen   REAL,
    resolved_at REAL,
    recurred    INTEGER DEFAULT 0,
    recurred_at REAL,             -- ts of the scan that triggered the most
                                   -- recent recurrence; NULL until then
    UNIQUE(host_key, cve_id, port)
);
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a DB was first created. Safe to run
        every startup; only adds what's missing.

        CREATE TABLE IF NOT EXISTS does not alter existing tables, so every
        column the current code reads/writes must be listed here (except the
        original primary key). Otherwise an older DB opens cleanly and then
        crashes on report queries (e.g. missing findings.cvss).
        """
        wanted = {
            "scans": [
                ("finished_at", "REAL"),
                ("profile", "TEXT"),
                ("targets", "TEXT"),
                ("host_count", "INTEGER DEFAULT 0"),
                ("hosts_attempted", "INTEGER"),
                ("hosts_failed", "INTEGER"),
                ("finding_count", "INTEGER DEFAULT 0"),
                # Existing finished rows predate status and are successful.
                ("status", "TEXT DEFAULT 'SUCCESS'"),
                ("error", "TEXT"),
            ],
            "hosts": [
                ("mac", "TEXT"),
                ("hostname", "TEXT"),
                ("vendor", "TEXT"),
                ("os_name", "TEXT"),
                ("os_accuracy", "INTEGER"),
                ("os_build", "TEXT"),
                ("device_type", "TEXT"),
                ("auth_method", "TEXT DEFAULT 'network'"),
                ("risk_score", "REAL DEFAULT 0"),
                ("vt_malicious", "INTEGER DEFAULT 0"),
            ],
            "services": [
                ("proto", "TEXT"),
                ("state", "TEXT"),
                ("service", "TEXT"),
                ("product", "TEXT"),
                ("version", "TEXT"),
                ("cpe", "TEXT"),
                ("source", "TEXT DEFAULT 'network'"),
            ],
            "findings": [
                ("service", "TEXT"),
                ("product", "TEXT"),
                ("version", "TEXT"),
                ("cpe", "TEXT"),
                ("cvss", "REAL"),
                ("severity", "TEXT"),
                ("is_kev", "INTEGER DEFAULT 0"),
                ("ransomware", "INTEGER DEFAULT 0"),
                ("epss", "REAL DEFAULT 0"),
                ("epss_pct", "REAL DEFAULT 0"),
                ("cwe", "TEXT"),
                ("cwe_name", "TEXT"),
                ("owasp_key", "TEXT"),
                ("owasp_name", "TEXT"),
                ("priority", "REAL DEFAULT 0"),
                ("summary", "TEXT"),
                ("remediation", "TEXT"),
                ("refs", "TEXT"),
                ("source", "TEXT DEFAULT 'network'"),
                ("status", "TEXT DEFAULT 'NEW'"),
            ],
            "resolved_findings": [
                ("ip", "TEXT"),
                ("port", "INTEGER"),
                ("severity", "TEXT"),
                ("is_kev", "INTEGER DEFAULT 0"),
                ("resolved_at", "REAL"),
            ],
            "finding_lifecycle": [
                ("first_seen", "REAL"),
                ("last_seen", "REAL"),
                ("resolved_at", "REAL"),
                ("recurred", "INTEGER DEFAULT 0"),
                ("recurred_at", "REAL"),
            ],
        }
        for table, cols in wanted.items():
            existing_rows = self._conn.execute(
                f"PRAGMA table_info({table})").fetchall()
            if not existing_rows:
                continue  # table created by SCHEMA this startup
            existing = {r["name"] for r in existing_rows}
            for name, decl in cols:
                if name not in existing:
                    self._conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ---- write path ---------------------------------------------------

    def create_scan(self, profile: str, targets: list[str]) -> int:
        with self.tx() as c:
            cur = c.execute(
                """INSERT INTO scans(started_at, profile, targets, status)
                   VALUES (?,?,?,'RUNNING')""",
                (time.time(), profile, json.dumps(targets)),
            )
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, host_count: int, finding_count: int,
                    hosts_attempted: int | None = None,
                    hosts_failed: int | None = None) -> None:
        with self.tx() as c:
            c.execute(
                "UPDATE scans SET finished_at=?, host_count=?, finding_count=?, "
                "hosts_attempted=?, hosts_failed=?, status='SUCCESS', error=NULL "
                "WHERE id=?",
                (time.time(), host_count, finding_count, hosts_attempted,
                 hosts_failed, scan_id),
            )

    def fail_scan(self, scan_id: int, error: str, host_count: int = 0,
                  finding_count: int = 0) -> None:
        """Finalize a failed scan without making it a report/baseline scan."""
        with self.tx() as c:
            c.execute(
                """UPDATE scans SET finished_at=?, host_count=?, finding_count=?,
                                  status='FAILED', error=?
                   WHERE id=?""",
                (time.time(), host_count, finding_count, error[:2000], scan_id),
            )

    def add_host(self, scan_id: int, host: dict[str, Any]) -> int:
        with self.tx() as c:
            cur = c.execute(
                """INSERT INTO hosts(scan_id, host_key, ip, mac, hostname, vendor,
                                     os_name, os_accuracy, os_build, device_type,
                                     auth_method, vt_malicious)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_id, host["host_key"], host["ip"], host.get("mac"),
                    host.get("hostname"), host.get("vendor"), host.get("os_name"),
                    host.get("os_accuracy"), host.get("os_build"),
                    host.get("device_type"), host.get("auth_method", "network"),
                    host.get("vt_malicious", 0),
                ),
            )
            return int(cur.lastrowid)

    def update_host_os(self, host_id: int, os_name: str | None,
                       os_build: str | None, auth_method: str) -> None:
        with self.tx() as c:
            c.execute(
                "UPDATE hosts SET os_name=COALESCE(?,os_name), "
                "os_build=COALESCE(?,os_build), auth_method=? WHERE id=?",
                (os_name, os_build, auth_method, host_id),
            )

    def add_fact(self, host_id: int, key: str, value: str) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO host_facts(host_id, key, value) VALUES (?,?,?)",
                      (host_id, key, value))

    def facts(self, host_id: int) -> dict[str, list[str]]:
        rows = self._conn.execute(
            "SELECT key, value FROM host_facts WHERE host_id=?", (host_id,)
        ).fetchall()
        out: dict[str, list[str]] = {}
        for r in rows:
            out.setdefault(r["key"], []).append(r["value"])
        return out

    def add_service(self, host_id: int, svc: dict[str, Any]) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT INTO services(host_id, port, proto, state, service,
                                        product, version, cpe, source)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (host_id, svc.get("port"), svc.get("proto"), svc.get("state"),
                 svc.get("service"), svc.get("product"), svc.get("version"),
                 svc.get("cpe"), svc.get("source", "network")),
            )

    def add_finding(self, scan_id: int, host_id: int, host_key: str,
                    f: dict[str, Any], status: str) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT INTO findings(scan_id, host_id, host_key, cve_id, port,
                        service, product, version, cpe, cvss, severity, is_kev,
                        ransomware, epss, epss_pct, cwe, cwe_name, owasp_key,
                        owasp_name, priority, summary, remediation, refs, source, status)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan_id, host_id, host_key, f["cve_id"], f.get("port"),
                 f.get("service"), f.get("product"), f.get("version"), f.get("cpe"),
                 f.get("cvss"), f.get("severity"), int(bool(f.get("is_kev"))),
                 int(bool(f.get("ransomware"))), f.get("epss", 0), f.get("epss_pct", 0),
                 f.get("cwe"), f.get("cwe_name"), f.get("owasp_key"),
                 f.get("owasp_name"), f.get("priority", 0),
                 f.get("summary"), json.dumps(f.get("remediation", [])),
                 json.dumps(f.get("refs", [])), f.get("source", "network"), status),
            )

    def set_host_risk(self, host_id: int, score: float) -> None:
        with self.tx() as c:
            c.execute("UPDATE hosts SET risk_score=? WHERE id=?", (score, host_id))

    def record_resolved(self, scan_id: int, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        with self.tx() as c:
            c.executemany(
                """INSERT INTO resolved_findings(scan_id, host_key, ip, cve_id,
                        port, severity, is_kev, resolved_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                [(scan_id, r["host_key"], r.get("ip"), r["cve_id"], r.get("port"),
                  r.get("severity"), int(bool(r.get("is_kev"))), time.time())
                 for r in rows],
            )

    def mark_lifecycle_seen(self, rows: list[dict[str, Any]], ts: float) -> None:
        """Upsert finding_lifecycle for each (host_key, cve_id, port) that was
        present in this scan. New keys get first_seen=last_seen=ts. Keys that
        were previously resolved and have now reappeared get recurred=1 and
        resolved_at cleared. Everything else just bumps last_seen."""
        if not rows:
            return
        with self.tx() as c:
            for r in rows:
                host_key = r["host_key"]
                cve_id = r["cve_id"]
                port = r.get("port") or 0
                existing = c.execute(
                    "SELECT resolved_at FROM finding_lifecycle "
                    "WHERE host_key=? AND cve_id=? AND port=?",
                    (host_key, cve_id, port),
                ).fetchone()
                if existing is None:
                    c.execute(
                        """INSERT INTO finding_lifecycle(host_key, cve_id, port,
                                first_seen, last_seen, resolved_at, recurred)
                           VALUES (?,?,?,?,?,NULL,0)""",
                        (host_key, cve_id, port, ts, ts),
                    )
                elif existing["resolved_at"] is not None:
                    c.execute(
                        """UPDATE finding_lifecycle
                           SET last_seen=?, resolved_at=NULL, recurred=1,
                               recurred_at=?
                           WHERE host_key=? AND cve_id=? AND port=?""",
                        (ts, ts, host_key, cve_id, port),
                    )
                else:
                    c.execute(
                        """UPDATE finding_lifecycle SET last_seen=?
                           WHERE host_key=? AND cve_id=? AND port=?""",
                        (ts, host_key, cve_id, port),
                    )

    def mark_lifecycle_resolved(self, rows: list[dict[str, Any]], ts: float) -> None:
        """Set resolved_at for each (host_key, cve_id, port) that is currently
        tracked as unresolved. Keys with no finding_lifecycle row are a no-op."""
        if not rows:
            return
        with self.tx() as c:
            c.executemany(
                """UPDATE finding_lifecycle SET resolved_at=?
                   WHERE host_key=? AND cve_id=? AND port=? AND resolved_at IS NULL""",
                [(ts, r["host_key"], r["cve_id"], r.get("port") or 0) for r in rows],
            )

    def open_lifecycle_findings(self) -> list[dict]:
        """Return still-open (unresolved) lifecycle rows.

        Used so a finding can be resolved when its host returns after being
        offline: comparing only to the immediately previous scan misses that
        case when the intervening scan saw the host down (and therefore had no
        prior finding row to resolve against).
        """
        return [dict(r) for r in self._conn.execute(
            """SELECT host_key, cve_id, port FROM finding_lifecycle
               WHERE resolved_at IS NULL"""
        ).fetchall()]

    # ---- read path ----------------------------------------------------

    def latest_scan_id(self) -> int | None:
        row = self._conn.execute(
            """SELECT id FROM scans
               WHERE finished_at IS NOT NULL AND status='SUCCESS'
               ORDER BY id DESC LIMIT 1"""
        ).fetchone()
        return int(row["id"]) if row else None

    def previous_scan_id(self, before: int) -> int | None:
        row = self._conn.execute(
            "SELECT id FROM scans WHERE id < ? AND finished_at IS NOT NULL "
            "AND status='SUCCESS' "
            "ORDER BY id DESC LIMIT 1",
            (before,),
        ).fetchone()
        return int(row["id"]) if row else None

    def prior_findings_keys(self, scan_id: int) -> set[tuple[str, str, int]]:
        """(host_key, cve_id, port) tuples from a given scan."""
        rows = self._conn.execute(
            "SELECT host_key, cve_id, port FROM findings WHERE scan_id=?", (scan_id,)
        ).fetchall()
        return {(r["host_key"], r["cve_id"], r["port"] or 0) for r in rows}

    def prior_findings_full(self, scan_id: int) -> dict[tuple[str, str, int], dict]:
        rows = self._conn.execute(
            """SELECT f.host_key, f.cve_id, f.port, f.severity, f.is_kev, h.ip
               FROM findings f JOIN hosts h ON h.id=f.host_id
               WHERE f.scan_id=?""",
            (scan_id,),
        ).fetchall()
        return {
            (r["host_key"], r["cve_id"], r["port"] or 0): dict(r) for r in rows
        }

    def scan(self, scan_id: int) -> dict | None:
        row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def is_successful_scan(self, scan_id: int) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM scans WHERE id=? AND status='SUCCESS'", (scan_id,)
        ).fetchone()
        return row is not None

    def all_scans(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            """SELECT * FROM scans
               WHERE finished_at IS NOT NULL AND status='SUCCESS'
               ORDER BY id DESC"""
        ).fetchall()]

    def hosts(self, scan_id: int) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM hosts WHERE scan_id=? ORDER BY risk_score DESC", (scan_id,)
        ).fetchall()]

    def host(self, host_id: int) -> dict | None:
        row = self._conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
        return dict(row) if row else None

    def services(self, host_id: int) -> list[dict]:
        """Network-visible services only (excludes pkg/os/info pseudo-entries)."""
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM services WHERE host_id=? AND proto NOT IN "
            "('pkg','os','info') ORDER BY port", (host_id,)
        ).fetchall()]

    def software(self, host_id: int) -> list[dict]:
        """Installed software gathered by credentialed scanning."""
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM services WHERE host_id=? AND proto='pkg' "
            "ORDER BY service", (host_id,)
        ).fetchall()]

    def info_services(self, host_id: int) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM services WHERE host_id=? AND proto='info'", (host_id,)
        ).fetchall()]

    def findings_for_host(self, host_id: int) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            """SELECT * FROM findings WHERE host_id=?
               ORDER BY priority DESC, is_kev DESC, cvss DESC""", (host_id,)
        ).fetchall()]

    def findings_grouped_by_cve(self, scan_id: int) -> list[dict]:
        rows = self._conn.execute(
            """SELECT cve_id,
                      MAX(cvss) AS cvss,
                      severity,
                      MAX(is_kev) AS is_kev,
                      MAX(ransomware) AS ransomware,
                      MAX(epss) AS epss,
                      MAX(epss_pct) AS epss_pct,
                      MAX(priority) AS priority,
                      cwe, cwe_name, owasp_key, owasp_name,
                      summary,
                      COUNT(DISTINCT host_id) AS host_count
               FROM findings WHERE scan_id=?
               GROUP BY cve_id
               ORDER BY priority DESC, is_kev DESC, cvss DESC""",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def findings_grouped_by_owasp(self, scan_id: int) -> list[dict]:
        rows = self._conn.execute(
            """SELECT owasp_key, owasp_name,
                      COUNT(*) AS finding_count,
                      COUNT(DISTINCT cve_id) AS cve_count,
                      COUNT(DISTINCT host_id) AS host_count,
                      MAX(is_kev) AS is_kev,
                      MAX(cvss) AS max_cvss
               FROM findings WHERE scan_id=?
               GROUP BY owasp_key, owasp_name
               ORDER BY finding_count DESC""",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def findings_grouped_by_cwe(self, scan_id: int) -> list[dict]:
        rows = self._conn.execute(
            """SELECT cwe, cwe_name, owasp_name,
                      COUNT(*) AS finding_count,
                      COUNT(DISTINCT cve_id) AS cve_count,
                      COUNT(DISTINCT host_id) AS host_count
               FROM findings WHERE scan_id=? AND cwe IS NOT NULL
               GROUP BY cwe, cwe_name
               ORDER BY finding_count DESC""",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def finding_by_cve(self, scan_id: int, cve_id: str) -> list[dict]:
        rows = self._conn.execute(
            """SELECT f.*, h.ip, h.hostname, h.id AS host_id
               FROM findings f JOIN hosts h ON h.id=f.host_id
               WHERE f.scan_id=? AND f.cve_id=?""",
            (scan_id, cve_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def resolved_for_scan(self, scan_id: int) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM resolved_findings WHERE scan_id=? ORDER BY is_kev DESC",
            (scan_id,)
        ).fetchall()]

    def lifecycle_trend(self, limit: int = 20) -> dict[int, dict]:
        """Per-scan finding_lifecycle counts, keyed by scan id, for the most
        recent `limit` finished scans: opened (first_seen fell within the
        scan's [started_at, finished_at] window), closed (counted from the
        append-only resolved_findings table, attributed by scan_id -- NOT
        from finding_lifecycle.resolved_at, which mark_lifecycle_seen clears
        back to NULL if the finding later recurs, which would otherwise make
        a scan's closed count retroactively drop to 0), and recurring
        (recurred=1 AND recurred_at fell within that window -- recurred_at is
        set only at the moment a resolved finding reappears, so unlike
        last_seen it doesn't keep advancing on every later scan the finding
        is merely still present in). Lets the /scans
        view surface findings opened vs. closed per scan and flag
        recurrences."""
        scans = self._conn.execute(
            "SELECT id, started_at, finished_at FROM scans "
            "WHERE finished_at IS NOT NULL AND status='SUCCESS' "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out: dict[int, dict] = {}
        for s in scans:
            sid, start, finish = s["id"], s["started_at"], s["finished_at"]
            opened = self._conn.execute(
                "SELECT COUNT(*) AS n FROM finding_lifecycle "
                "WHERE first_seen BETWEEN ? AND ?", (start, finish),
            ).fetchone()["n"]
            closed = self._conn.execute(
                "SELECT COUNT(*) AS n FROM resolved_findings WHERE scan_id=?",
                (sid,),
            ).fetchone()["n"]
            recurring = self._conn.execute(
                "SELECT COUNT(*) AS n FROM finding_lifecycle "
                "WHERE recurred=1 AND recurred_at BETWEEN ? AND ?", (start, finish),
            ).fetchone()["n"]
            out[sid] = {"opened": opened, "closed": closed, "recurring": recurring}
        return out

    def summary(self, scan_id: int) -> dict:
        s = self._conn.execute(
            """SELECT
                 COUNT(*) AS total,
                 SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) AS critical,
                 SUM(CASE WHEN severity='High' THEN 1 ELSE 0 END) AS high,
                 SUM(CASE WHEN severity='Medium' THEN 1 ELSE 0 END) AS medium,
                 SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END) AS low,
                 SUM(is_kev) AS kev
               FROM findings WHERE scan_id=?""",
            (scan_id,),
        ).fetchone()
        hosts = self._conn.execute(
            "SELECT COUNT(*) AS n FROM hosts WHERE scan_id=?", (scan_id,)
        ).fetchone()
        resolved = self._conn.execute(
            "SELECT COUNT(*) AS n FROM resolved_findings WHERE scan_id=?", (scan_id,)
        ).fetchone()
        d = {k: (s[k] or 0) for k in s.keys()}
        d["hosts"] = hosts["n"] or 0
        d["resolved"] = resolved["n"] or 0
        return d
