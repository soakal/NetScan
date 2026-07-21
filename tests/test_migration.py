"""Migration-safety test for netscan.db.

Simulates opening a database that was created before the finding_lifecycle
table existed: builds a minimal "old" schema (scans/hosts/findings only,
no finding_lifecycle), seeds it with sample rows using a bare sqlite3
connection, then reopens it through Database() -- the same code path a real
upgrade takes. Database() runs SCHEMA (CREATE TABLE IF NOT EXISTS ...) and
_migrate() on every startup, so this exercises exactly what happens when an
existing user's DB is opened by the new code.

Asserts:
  1. finding_lifecycle now exists (PRAGMA table_info returns columns).
  2. Every pre-existing scans/hosts/findings row is still there untouched --
     i.e. the additive schema change causes zero data loss.
"""
from __future__ import annotations

import sqlite3

from netscan.db import Database

# Minimal stand-in for the schema as it existed before finding_lifecycle was
# added. Deliberately narrower than the real SCHEMA (only the columns this
# test touches) -- the point is that these tables/rows pre-exist and must
# survive Database() being pointed at them.
OLD_SCHEMA = """
CREATE TABLE scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   REAL NOT NULL,
    finished_at  REAL,
    profile      TEXT,
    targets      TEXT,
    host_count   INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0
);

CREATE TABLE hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    host_key    TEXT NOT NULL,
    ip          TEXT NOT NULL,
    mac         TEXT,
    hostname    TEXT,
    vendor      TEXT,
    os_name     TEXT,
    os_accuracy INTEGER,
    device_type TEXT,
    risk_score  REAL DEFAULT 0,
    vt_malicious INTEGER DEFAULT 0,
    UNIQUE(scan_id, host_key)
);

CREATE TABLE findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    host_id     INTEGER NOT NULL REFERENCES hosts(id),
    host_key    TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    port        INTEGER,
    severity    TEXT,
    is_kev      INTEGER DEFAULT 0,
    status      TEXT DEFAULT 'NEW'
);
"""


def _seed_old_db(path: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(OLD_SCHEMA)
        conn.execute(
            "INSERT INTO scans(started_at, finished_at, profile, targets, "
            "host_count, finding_count) VALUES (1.0, 2.0, 'default', '[]', 1, 1)"
        )
        conn.execute(
            "INSERT INTO hosts(scan_id, host_key, ip) VALUES (1, 'aa:bb:cc', '10.0.0.1')"
        )
        conn.execute(
            "INSERT INTO findings(scan_id, host_id, host_key, cve_id, port, "
            "severity, is_kev, status) VALUES "
            "(1, 1, 'aa:bb:cc', 'CVE-2024-0001', 443, 'High', 0, 'NEW')"
        )
        conn.commit()
    finally:
        conn.close()


# Fixed set of literal queries for the only tables this test ever touches.
# No SQL string is ever built by interpolating a table name -- callers can
# only select one of these pre-written statements, so there is no
# string-based query construction for a scanner (or a future contributor)
# to worry about.
_TABLE_INFO_QUERIES = {
    "scans": "PRAGMA table_info(scans)",
    "hosts": "PRAGMA table_info(hosts)",
    "findings": "PRAGMA table_info(findings)",
    "finding_lifecycle": "PRAGMA table_info(finding_lifecycle)",
}
_COUNT_QUERIES = {
    "scans": "SELECT COUNT(*) FROM scans",
    "hosts": "SELECT COUNT(*) FROM hosts",
    "findings": "SELECT COUNT(*) FROM findings",
    "finding_lifecycle": "SELECT COUNT(*) FROM finding_lifecycle",
}


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cols = conn.execute(_TABLE_INFO_QUERIES[name]).fetchall()
    return len(cols) > 0


def _row_count(conn: sqlite3.Connection, table: str) -> int:
    return conn.execute(_COUNT_QUERIES[table]).fetchone()[0]


def test_migration_adds_finding_lifecycle_without_data_loss(tmp_path):
    db_path = str(tmp_path / "old.db")

    # 1. Seed a DB using the pre-finding_lifecycle schema.
    _seed_old_db(db_path)

    raw = sqlite3.connect(db_path)
    try:
        assert not _table_exists(raw, "finding_lifecycle")
        pre_scans = _row_count(raw, "scans")
        pre_hosts = _row_count(raw, "hosts")
        pre_findings = _row_count(raw, "findings")
    finally:
        raw.close()

    assert (pre_scans, pre_hosts, pre_findings) == (1, 1, 1)

    # 2. Reopen through the real Database() -- this runs SCHEMA + _migrate().
    db = Database(db_path)
    try:
        # (a) finding_lifecycle now exists.
        cols = {r["name"] for r in db._conn.execute(
            "PRAGMA table_info(finding_lifecycle)").fetchall()}
        assert cols == {
            "id", "host_key", "cve_id", "port",
            "first_seen", "last_seen", "resolved_at", "recurred",
        }

        # It's empty -- nothing populates it yet.
        assert _row_count(db._conn, "finding_lifecycle") == 0

        # (b) pre-existing rows are untouched.
        assert _row_count(db._conn, "scans") == pre_scans
        assert _row_count(db._conn, "hosts") == pre_hosts
        assert _row_count(db._conn, "findings") == pre_findings
    finally:
        db.close()
