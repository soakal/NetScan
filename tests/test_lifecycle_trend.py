"""Tests for Database.lifecycle_trend(), the per-scan opened/closed/recurring
rollup read by the /scans view.

Builds a real sqlite db via create_scan()/finish_scan() (so started_at/
finished_at come from the real write path) plus raw finding_lifecycle inserts
timed to land inside a specific scan's [started_at, finished_at] window, then
asserts lifecycle_trend() buckets each finding_lifecycle row under the right
scan id.
"""
from __future__ import annotations

from netscan.db import Database


def _insert_lifecycle(db: Database, host_key, cve_id, port, first_seen,
                       last_seen, resolved_at=None, recurred=0):
    with db.tx() as c:
        c.execute(
            """INSERT INTO finding_lifecycle(host_key, cve_id, port,
                    first_seen, last_seen, resolved_at, recurred)
               VALUES (?,?,?,?,?,?,?)""",
            (host_key, cve_id, port or 0, first_seen, last_seen, resolved_at,
             recurred),
        )


def _set_scan_window(db: Database, scan_id, started_at, finished_at):
    with db.tx() as c:
        c.execute(
            "UPDATE scans SET started_at=?, finished_at=? WHERE id=?",
            (started_at, finished_at, scan_id),
        )


def test_lifecycle_trend_buckets_opened_closed_recurring_per_scan(tmp_path):
    db = Database(str(tmp_path / "trend.db"))
    try:
        # scan 1: window [0, 10] -- a finding opens here
        scan1 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan1, host_count=1, finding_count=1)
        _set_scan_window(db, scan1, 0.0, 10.0)

        # scan 2: window [20, 30] -- that finding closes here, and an
        # unrelated finding both opens and recurs here
        scan2 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan2, host_count=1, finding_count=1)
        _set_scan_window(db, scan2, 20.0, 30.0)

        # scan 3: window [40, 50] -- nothing happens in this window
        scan3 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan3, host_count=1, finding_count=0)
        _set_scan_window(db, scan3, 40.0, 50.0)

        # Finding A: opened in scan1's window, closed in scan2's window.
        _insert_lifecycle(db, "aa:bb:cc", "CVE-2024-0001", 443,
                           first_seen=5.0, last_seen=5.0, resolved_at=25.0)

        # Finding B: opened AND recurring inside scan2's window (simulates
        # a finding that was resolved earlier -- outside any tracked
        # scan window here -- and reappears during scan2).
        _insert_lifecycle(db, "dd:ee:ff", "CVE-2024-0002", 80,
                           first_seen=22.0, last_seen=22.0, resolved_at=None,
                           recurred=1)

        trend = db.lifecycle_trend()

        assert trend[scan1] == {"opened": 1, "closed": 0, "recurring": 0}
        assert trend[scan2] == {"opened": 1, "closed": 1, "recurring": 1}
        assert trend[scan3] == {"opened": 0, "closed": 0, "recurring": 0}
    finally:
        db.close()


def test_lifecycle_trend_recurring_only_counted_when_recurred_flag_set(tmp_path):
    db = Database(str(tmp_path / "trend2.db"))
    try:
        scan1 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan1, host_count=1, finding_count=1)
        _set_scan_window(db, scan1, 0.0, 10.0)

        # last_seen falls in the window, but recurred=0 -- must NOT count
        # towards "recurring".
        _insert_lifecycle(db, "11:22:33", "CVE-2024-0003", 22,
                           first_seen=1.0, last_seen=5.0, recurred=0)

        trend = db.lifecycle_trend()
        assert trend[scan1]["recurring"] == 0
        assert trend[scan1]["opened"] == 1  # first_seen=1.0 is in [0,10]

    finally:
        db.close()


def test_lifecycle_trend_limit_and_unfinished_scans(tmp_path):
    db = Database(str(tmp_path / "trend3.db"))
    try:
        scan1 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan1, host_count=0, finding_count=0)
        _set_scan_window(db, scan1, 0.0, 10.0)

        # An unfinished scan (no finished_at) must be excluded entirely.
        db.create_scan("light", ["10.0.0.0/24"])

        trend = db.lifecycle_trend(limit=20)
        assert list(trend.keys()) == [scan1]
    finally:
        db.close()
