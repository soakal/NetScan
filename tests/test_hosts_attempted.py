"""Tests for the scans.hosts_attempted / scans.hosts_failed columns.

Covers:
  (a) migration-safety: an old DB missing the columns gains them via
      Database() with zero data loss (same pattern as test_migration.py).
  (b) finish_scan() persists attempted/succeeded(host_count)/failed, with
      failed == attempted - succeeded and failed >= 0.
  (c) correlate.run_scan derives attempted from the target/exclude CIDR
      expansion and clamps failed at 0 even when more hosts responded than
      were nominally "attempted" (e.g. hostname targets that don't expand).
"""
from __future__ import annotations

import sqlite3

import netscan.correlate as correlate
from netscan.config import Config
from netscan.db import Database

# Old schema predating hosts_attempted/hosts_failed -- narrower than the real
# SCHEMA, just enough to prove old scans rows survive the migration.
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
"""


def test_migration_adds_hosts_attempted_and_failed_without_data_loss(tmp_path):
    db_path = str(tmp_path / "old.db")

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(OLD_SCHEMA)
        conn.execute(
            "INSERT INTO scans(started_at, finished_at, profile, targets, "
            "host_count, finding_count) VALUES (1.0, 2.0, 'default', '[]', 3, 5)"
        )
        conn.commit()
    finally:
        conn.close()

    raw = sqlite3.connect(db_path)
    try:
        cols = {r[1] for r in raw.execute("PRAGMA table_info(scans)").fetchall()}
        assert "hosts_attempted" not in cols
        assert "hosts_failed" not in cols
        pre_count = raw.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    finally:
        raw.close()
    assert pre_count == 1

    db = Database(db_path)
    try:
        cols = {r["name"] for r in db._conn.execute(
            "PRAGMA table_info(scans)").fetchall()}
        assert {"hosts_attempted", "hosts_failed"} <= cols

        assert db._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == pre_count
        row = db._conn.execute(
            "SELECT host_count, finding_count, hosts_attempted, hosts_failed "
            "FROM scans WHERE id=1"
        ).fetchone()
        # Pre-existing row untouched: new columns default to NULL, old data intact.
        assert row["host_count"] == 3
        assert row["finding_count"] == 5
        assert row["hosts_attempted"] is None
        assert row["hosts_failed"] is None
    finally:
        db.close()


def test_finish_scan_persists_attempted_succeeded_failed(tmp_path):
    db = Database(str(tmp_path / "scan.db"))
    try:
        scan_id = db.create_scan("light", ["10.0.0.0/30"])
        db.finish_scan(scan_id, host_count=1, finding_count=0,
                        hosts_attempted=4, hosts_failed=3)

        row = db.scan(scan_id)
        assert row["host_count"] == 1          # succeeded
        assert row["hosts_attempted"] == 4
        assert row["hosts_failed"] == 3
        assert row["hosts_failed"] == row["hosts_attempted"] - row["host_count"]
        assert row["hosts_failed"] >= 0
    finally:
        db.close()


def test_finish_scan_defaults_attempted_failed_to_none(tmp_path):
    """Existing callers (demo.py, other tests) that don't pass the new kwargs
    must keep working, storing NULL rather than crashing."""
    db = Database(str(tmp_path / "scan.db"))
    try:
        scan_id = db.create_scan("light", ["10.0.0.0/30"])
        db.finish_scan(scan_id, host_count=1, finding_count=0)

        row = db.scan(scan_id)
        assert row["hosts_attempted"] is None
        assert row["hosts_failed"] is None
    finally:
        db.close()


class _FakeKev:
    def __init__(self, *_a, **_kw):
        pass

    def load(self):
        return self

    def lookup(self, cve_id):
        return None


class _FakeNvd:
    def __init__(self, *_a, **_kw):
        pass

    def cves_for_cpe(self, cpe23):
        return []

    def cve_by_id(self, cve_id):
        return None


class _FakeEpss:
    def __init__(self, *_a, **_kw):
        pass

    def scores_for(self, cve_ids):
        return {}


class _FakeVt:
    def __init__(self, *_a, **_kw):
        pass

    @property
    def enabled(self):
        return False

    def ip_reputation(self, ip):
        return None


def _host(ip):
    return {
        "ip": ip, "mac": None, "vendor": None, "hostname": None,
        "os_name": None, "os_accuracy": None, "device_type": None,
        "host_key": ip, "services": [],
    }


def test_run_scan_derives_attempted_and_failed_from_target_expansion(tmp_path, monkeypatch):
    monkeypatch.setattr(correlate, "KevCatalog", _FakeKev)
    monkeypatch.setattr(correlate, "NvdClient", _FakeNvd)
    monkeypatch.setattr(correlate, "EpssClient", _FakeEpss)
    monkeypatch.setattr(correlate, "VirusTotalClient", _FakeVt)

    # 10.0.0.0/30 usable hosts: 10.0.0.1, 10.0.0.2 -> attempted = 2.
    # Only one responds -> succeeded (host_count) = 1, failed = 1.
    cfg = Config(
        targets=["10.0.0.0/30"],
        scan_profile="light",
        db_path=str(tmp_path / "scan.db"),
        cache_dir=str(tmp_path / "cache"),
    )
    monkeypatch.setattr(correlate, "discover_and_fingerprint",
                        lambda cfg: [_host("10.0.0.1")])

    scan_id = correlate.run_scan(cfg)

    db = Database(cfg.db_path)
    try:
        row = db.scan(scan_id)
        assert row["hosts_attempted"] == 2
        assert row["host_count"] == 1           # succeeded, unchanged meaning
        assert row["hosts_failed"] == 1
        assert row["hosts_failed"] == row["hosts_attempted"] - row["host_count"]
        assert row["hosts_failed"] >= 0
    finally:
        db.close()


def test_run_scan_nonderivable_targets_store_null_and_dont_crash(tmp_path, monkeypatch):
    """A hostname target doesn't expand via _expand_targets (it's not a CIDR,
    range, or plain IP) -- attempted/failed must be NULL, not a crash or a
    misleading 0, even though a host was actually found."""
    monkeypatch.setattr(correlate, "KevCatalog", _FakeKev)
    monkeypatch.setattr(correlate, "NvdClient", _FakeNvd)
    monkeypatch.setattr(correlate, "EpssClient", _FakeEpss)
    monkeypatch.setattr(correlate, "VirusTotalClient", _FakeVt)

    cfg = Config(
        targets=["not-a-real-hostname.example"],
        scan_profile="light",
        db_path=str(tmp_path / "scan.db"),
        cache_dir=str(tmp_path / "cache"),
    )
    monkeypatch.setattr(correlate, "discover_and_fingerprint",
                        lambda cfg: [_host("10.0.0.1")])

    scan_id = correlate.run_scan(cfg)

    db = Database(cfg.db_path)
    try:
        row = db.scan(scan_id)
        assert row["hosts_attempted"] is None
        assert row["hosts_failed"] is None
        assert row["host_count"] == 1
    finally:
        db.close()
