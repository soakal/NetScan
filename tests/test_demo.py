"""Regression test: demo.seed() must populate finding_lifecycle too, not just
findings -- otherwise the /scans trend view (Opened/Closed/Recurring) shows
0/0/0 for the very first thing a new user is told to try (see run.py's demo
command and RUNNING.md)."""
from __future__ import annotations

from netscan.db import Database
from netscan.demo import seed


def test_demo_seed_populates_lifecycle(tmp_path):
    db_path = str(tmp_path / "demo.db")
    n = seed(db_path)
    assert n > 0

    db = Database(db_path)
    try:
        rows = db._conn.execute("SELECT * FROM finding_lifecycle").fetchall()
        assert len(rows) == n, "every seeded finding should have a lifecycle row"
        for r in rows:
            assert r["first_seen"] == r["last_seen"]
            assert r["resolved_at"] is None
            assert r["recurred"] == 0

        scan = db._conn.execute("SELECT id, hosts_attempted, hosts_failed, host_count "
                                "FROM scans").fetchone()
        assert scan["hosts_attempted"] == scan["host_count"]
        assert scan["hosts_failed"] == 0

        trend = db.lifecycle_trend()
        assert trend[scan["id"]]["opened"] == n
    finally:
        db.close()
