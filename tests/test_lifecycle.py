"""Tests for the finding_lifecycle upsert methods on netscan.db.Database.

Drives mark_lifecycle_seen()/mark_lifecycle_resolved() directly against a real
sqlite file (no mocks) through the four transitions the lifecycle table is
meant to track for a single (host_key, cve_id, port) key:

  1. new       -> first appearance inserts first_seen == last_seen == ts,
                  resolved_at NULL, recurred 0.
  2. persist   -> seeing it again just bumps last_seen; resolved_at stays
                  NULL and first_seen is unchanged.
  3. resolve   -> mark_lifecycle_resolved() sets resolved_at.
  4. recur     -> seeing it again after being resolved sets recurred=1 and
                  clears resolved_at, while first_seen from step 1 survives.
"""
from __future__ import annotations

from netscan.db import Database

KEY_ROW = {"host_key": "aa:bb:cc", "cve_id": "CVE-2024-0001", "port": 443}


def _lifecycle_row(db: Database, row: dict = KEY_ROW) -> dict:
    r = db._conn.execute(
        "SELECT * FROM finding_lifecycle WHERE host_key=? AND cve_id=? AND port=?",
        (row["host_key"], row["cve_id"], row["port"] or 0),
    ).fetchone()
    assert r is not None, "expected a finding_lifecycle row to exist"
    return dict(r)


def test_mark_lifecycle_seen_inserts_first_seen(tmp_path):
    db = Database(str(tmp_path / "lifecycle.db"))
    try:
        db.mark_lifecycle_seen([KEY_ROW], ts=100.0)

        row = _lifecycle_row(db)
        assert row["first_seen"] == 100.0
        assert row["last_seen"] == 100.0
        assert row["resolved_at"] is None
        assert row["recurred"] == 0
    finally:
        db.close()


def test_mark_lifecycle_seen_again_persists_and_bumps_last_seen(tmp_path):
    db = Database(str(tmp_path / "lifecycle.db"))
    try:
        db.mark_lifecycle_seen([KEY_ROW], ts=100.0)
        db.mark_lifecycle_seen([KEY_ROW], ts=200.0)

        row = _lifecycle_row(db)
        assert row["first_seen"] == 100.0        # unchanged
        assert row["last_seen"] == 200.0          # bumped
        assert row["resolved_at"] is None
        assert row["recurred"] == 0

        # Still exactly one row for this key -- an UPSERT, not a duplicate.
        count = db._conn.execute(
            "SELECT COUNT(*) AS n FROM finding_lifecycle"
        ).fetchone()["n"]
        assert count == 1
    finally:
        db.close()


def test_mark_lifecycle_resolved_sets_resolved_at(tmp_path):
    db = Database(str(tmp_path / "lifecycle.db"))
    try:
        db.mark_lifecycle_seen([KEY_ROW], ts=100.0)
        db.mark_lifecycle_resolved([KEY_ROW], ts=150.0)

        row = _lifecycle_row(db)
        assert row["resolved_at"] == 150.0
        assert row["recurred"] == 0
    finally:
        db.close()


def test_mark_lifecycle_resolved_noop_when_not_tracked(tmp_path):
    db = Database(str(tmp_path / "lifecycle.db"))
    try:
        # Nothing has ever been marked seen for this key -- resolving it
        # should not create a row.
        db.mark_lifecycle_resolved([KEY_ROW], ts=150.0)

        row = db._conn.execute(
            "SELECT * FROM finding_lifecycle WHERE host_key=? AND cve_id=? AND port=?",
            (KEY_ROW["host_key"], KEY_ROW["cve_id"], KEY_ROW["port"]),
        ).fetchone()
        assert row is None
    finally:
        db.close()


def test_reappearance_after_resolve_sets_recurred_and_clears_resolved_at(tmp_path):
    db = Database(str(tmp_path / "lifecycle.db"))
    try:
        db.mark_lifecycle_seen([KEY_ROW], ts=100.0)          # new
        db.mark_lifecycle_resolved([KEY_ROW], ts=150.0)      # resolved
        db.mark_lifecycle_seen([KEY_ROW], ts=300.0)          # recurs

        row = _lifecycle_row(db)
        assert row["first_seen"] == 100.0     # original first_seen preserved
        assert row["last_seen"] == 300.0
        assert row["resolved_at"] is None      # cleared on recurrence
        assert row["recurred"] == 1
    finally:
        db.close()


def test_port_none_normalizes_to_zero(tmp_path):
    """port-less findings (port=None) must key the same as port=0, matching
    the `port or 0` convention used elsewhere (prior_findings_keys etc.)."""
    db = Database(str(tmp_path / "lifecycle.db"))
    try:
        row_none = {"host_key": "aa:bb:cc", "cve_id": "CVE-2024-0002", "port": None}
        db.mark_lifecycle_seen([row_none], ts=100.0)

        r = db._conn.execute(
            "SELECT * FROM finding_lifecycle WHERE host_key=? AND cve_id=? AND port=0",
            (row_none["host_key"], row_none["cve_id"]),
        ).fetchone()
        assert r is not None
        assert r["port"] == 0
    finally:
        db.close()
