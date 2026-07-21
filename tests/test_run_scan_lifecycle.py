"""End-to-end test that netscan.correlate.run_scan actually wires the
finding_lifecycle table across real scans (not just the direct db.py unit
tests in test_lifecycle.py, which never exercise run_scan itself).

Runs run_scan() three times against a temp sqlite db with the network-facing
collaborators (discover_and_fingerprint, KevCatalog, NvdClient, EpssClient,
VirusTotalClient) monkeypatched to deterministic offline stand-ins, so no
real network I/O happens:

  scan 1: the vulnerable host/service is present  -> finding created,
          finding_lifecycle row inserted (first_seen == last_seen == ts1).
  scan 2: the host disappears (down / patched)     -> resolved_findings row
          written and finding_lifecycle.resolved_at set.
  scan 3: the finding reappears                    -> finding_lifecycle shows
          recurred=1, resolved_at cleared again, first_seen still == ts1.
"""
from __future__ import annotations

import netscan.correlate as correlate
from netscan.config import Config

HOST_KEY = "aa:bb:cc:dd:ee:ff"
CVE_ID = "CVE-2099-0001"
CPE = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"


def _host():
    return {
        "ip": "10.0.0.5", "mac": HOST_KEY, "vendor": None, "hostname": "widget-host",
        "os_name": None, "os_accuracy": None, "device_type": None,
        "host_key": HOST_KEY,
        "services": [{
            "port": 443, "proto": "tcp", "state": "open", "service": "https",
            "product": "widget", "version": "1.0", "cpe": CPE, "cpes": [CPE],
        }],
    }


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
        if cpe23 != CPE:
            return []
        return [{
            "cve_id": CVE_ID, "summary": "Fake test CVE.", "cvss": 7.5,
            "cvss_vector": None, "cvss_version": None, "severity": "High",
            "cwes": [], "refs": [], "published": None,
        }]

    def cve_by_id(self, cve_id):
        return None


class _FakeEpss:
    def __init__(self, *_a, **_kw):
        pass

    def scores_for(self, cve_ids):
        return {cid.upper(): {"epss": 0.1, "percentile": 0.5} for cid in cve_ids}


class _FakeVt:
    def __init__(self, *_a, **_kw):
        pass

    @property
    def enabled(self):
        return False

    def ip_reputation(self, ip):
        return None


def _make_cfg(tmp_path):
    return Config(
        targets=["10.0.0.5"],
        scan_profile="light",
        db_path=str(tmp_path / "scan.db"),
        cache_dir=str(tmp_path / "cache"),
    )


def _lifecycle_row(cfg):
    from netscan.db import Database
    db = Database(cfg.db_path)
    try:
        r = db._conn.execute(
            "SELECT * FROM finding_lifecycle WHERE host_key=? AND cve_id=? AND port=?",
            (HOST_KEY, CVE_ID, 443),
        ).fetchone()
        return dict(r) if r else None
    finally:
        db.close()


def test_run_scan_wires_finding_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(correlate, "KevCatalog", _FakeKev)
    monkeypatch.setattr(correlate, "NvdClient", _FakeNvd)
    monkeypatch.setattr(correlate, "EpssClient", _FakeEpss)
    monkeypatch.setattr(correlate, "VirusTotalClient", _FakeVt)

    cfg = _make_cfg(tmp_path)

    # --- scan 1: finding present -------------------------------------------------
    monkeypatch.setattr(correlate, "discover_and_fingerprint", lambda cfg: [_host()])
    correlate.run_scan(cfg)

    row1 = _lifecycle_row(cfg)
    assert row1 is not None, "expected a finding_lifecycle row after scan 1"
    assert row1["first_seen"] == row1["last_seen"]
    assert row1["resolved_at"] is None
    assert row1["recurred"] == 0
    first_seen = row1["first_seen"]

    # --- scan 2: host/finding absent (down or fixed) -----------------------------
    monkeypatch.setattr(correlate, "discover_and_fingerprint", lambda cfg: [])
    correlate.run_scan(cfg)

    row2 = _lifecycle_row(cfg)
    assert row2 is not None
    assert row2["first_seen"] == first_seen        # unchanged
    assert row2["resolved_at"] is not None          # resolved after disappearance
    assert row2["recurred"] == 0

    # --- scan 3: finding reappears ------------------------------------------------
    monkeypatch.setattr(correlate, "discover_and_fingerprint", lambda cfg: [_host()])
    correlate.run_scan(cfg)

    row3 = _lifecycle_row(cfg)
    assert row3 is not None
    assert row3["first_seen"] == first_seen         # preserved across the whole run
    assert row3["resolved_at"] is None               # cleared on recurrence
    assert row3["recurred"] == 1
