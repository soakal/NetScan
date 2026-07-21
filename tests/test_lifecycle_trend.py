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
                       last_seen, resolved_at=None, recurred=0,
                       recurred_at=None):
    with db.tx() as c:
        c.execute(
            """INSERT INTO finding_lifecycle(host_key, cve_id, port,
                    first_seen, last_seen, resolved_at, recurred, recurred_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (host_key, cve_id, port or 0, first_seen, last_seen, resolved_at,
             recurred, recurred_at),
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
        # "closed" is sourced from resolved_findings (scan-attributed), not
        # from finding_lifecycle.resolved_at, so both must be populated here.
        _insert_lifecycle(db, "aa:bb:cc", "CVE-2024-0001", 443,
                           first_seen=5.0, last_seen=5.0, resolved_at=25.0)
        db.record_resolved(scan2, [{"host_key": "aa:bb:cc",
                                    "cve_id": "CVE-2024-0001", "port": 443,
                                    "severity": "High", "is_kev": 0}])

        # Finding B: opened AND recurring inside scan2's window (simulates
        # a finding that was resolved earlier -- outside any tracked
        # scan window here -- and reappears during scan2). recurred_at is
        # what "recurring" windows on, so it must be set to when the
        # recurrence happened, same as first_seen/last_seen here.
        _insert_lifecycle(db, "dd:ee:ff", "CVE-2024-0002", 80,
                           first_seen=22.0, last_seen=22.0, resolved_at=None,
                           recurred=1, recurred_at=22.0)

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


def test_lifecycle_trend_closed_count_survives_later_recurrence(tmp_path):
    """Regression test for the bug where a scan's 'closed' count would
    retroactively drop to 0 once a resolved finding later recurred.

    finding_lifecycle.resolved_at gets CLEARED to NULL by
    mark_lifecycle_seen's recurrence branch when a resolved finding
    reappears. Since 'closed' used to be computed from
    `resolved_at BETWEEN scan.started_at AND scan.finished_at`, scan 2's
    closed count would silently become 0 once scan 3 caused the recurrence.
    'closed' must instead be sourced from the append-only resolved_findings
    table (scan_id-attributed), which is never mutated after insert.

    Sequence, driven through the real write-path methods (mirroring what
    correlate.py does): finding opens in scan 1, resolves in scan 2 (via
    record_resolved + mark_lifecycle_resolved), then recurs in scan 3 (via
    mark_lifecycle_seen), which clears finding_lifecycle.resolved_at and
    sets recurred=1.
    """
    db = Database(str(tmp_path / "trend_regression.db"))
    try:
        host_key, cve_id, port = "aa:bb:cc", "CVE-2024-0099", 443
        row = {"host_key": host_key, "cve_id": cve_id, "port": port}

        # scan 1: window [0, 10] -- finding opens here.
        scan1 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan1, host_count=1, finding_count=1)
        _set_scan_window(db, scan1, 0.0, 10.0)
        db.mark_lifecycle_seen([row], 5.0)

        # scan 2: window [20, 30] -- finding resolves here (present in
        # scan 1, absent in scan 2 -- exactly what correlate.py detects and
        # feeds into record_resolved/mark_lifecycle_resolved).
        scan2 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan2, host_count=1, finding_count=0)
        _set_scan_window(db, scan2, 20.0, 30.0)
        db.record_resolved(scan2, [{**row, "severity": "High", "is_kev": 0}])
        db.mark_lifecycle_resolved([row], 25.0)

        # Sanity check: closed count is correct immediately after scan 2,
        # before any recurrence has happened.
        trend = db.lifecycle_trend()
        assert trend[scan2]["closed"] == 1

        # scan 3: window [40, 50] -- finding recurs here. This clears
        # finding_lifecycle.resolved_at back to NULL and sets recurred=1.
        scan3 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan3, host_count=1, finding_count=1)
        _set_scan_window(db, scan3, 40.0, 50.0)
        db.mark_lifecycle_seen([row], 45.0)

        # The regression: scan 2's closed count must STILL be 1 -- the
        # historical closure must not vanish just because the finding later
        # recurred and cleared the mutable resolved_at column.
        trend = db.lifecycle_trend()
        assert trend[scan2]["closed"] == 1
        assert trend[scan1]["opened"] == 1
        assert trend[scan3]["recurring"] == 1
    finally:
        db.close()


def test_lifecycle_trend_recurring_does_not_bleed_into_later_scans(tmp_path):
    """Regression test: 'recurring' must be attributed to the scan where the
    recurrence actually happened, not to every later scan the finding merely
    remains present in.

    Sequence, driven through the real write-path methods: finding opens in
    scan 1, resolves in scan 2, recurs in scan 3 (mark_lifecycle_seen's
    recurrence branch), then just stays present in scan 4. Before this fix,
    'recurring' windowed on last_seen -- which keeps advancing every scan the
    finding is merely still present in -- so recurred=1 would bleed forward
    and scan 4 would incorrectly also show recurring=1.
    """
    db = Database(str(tmp_path / "trend_recur_bleed.db"))
    try:
        host_key, cve_id, port = "aa:bb:cc", "CVE-2024-0100", 8080
        row = {"host_key": host_key, "cve_id": cve_id, "port": port}

        # scan 1: window [0, 10] -- finding opens here.
        scan1 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan1, host_count=1, finding_count=1)
        _set_scan_window(db, scan1, 0.0, 10.0)
        db.mark_lifecycle_seen([row], 5.0)

        # scan 2: window [20, 30] -- finding resolves here.
        scan2 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan2, host_count=1, finding_count=0)
        _set_scan_window(db, scan2, 20.0, 30.0)
        db.record_resolved(scan2, [{**row, "severity": "High", "is_kev": 0}])
        db.mark_lifecycle_resolved([row], 25.0)

        # scan 3: window [40, 50] -- finding recurs here.
        scan3 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan3, host_count=1, finding_count=1)
        _set_scan_window(db, scan3, 40.0, 50.0)
        db.mark_lifecycle_seen([row], 45.0)

        # scan 4: window [60, 70] -- finding is simply still present;
        # last_seen advances again but this is NOT a new recurrence.
        scan4 = db.create_scan("light", ["10.0.0.0/24"])
        db.finish_scan(scan4, host_count=1, finding_count=1)
        _set_scan_window(db, scan4, 60.0, 70.0)
        db.mark_lifecycle_seen([row], 65.0)

        trend = db.lifecycle_trend()
        assert trend[scan3]["recurring"] == 1
        assert trend[scan4]["recurring"] == 0
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
