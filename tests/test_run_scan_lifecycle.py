"""End-to-end test that netscan.correlate.run_scan actually wires the
finding_lifecycle table across real scans (not just the direct db.py unit
tests in test_lifecycle.py, which never exercise run_scan itself).

Runs run_scan() against a temp sqlite db with the network-facing
collaborators (discover_and_fingerprint, KevCatalog, NvdClient, EpssClient,
VirusTotalClient) monkeypatched to deterministic offline stand-ins, so no
real network I/O happens.

Two scenarios matter here and must NOT be conflated (see
test_run_scan_host_down_does_not_resolve_findings for why):

  - the host responds and the vulnerable service is genuinely gone (patched)
    -> that's a real resolution, finding_lifecycle.resolved_at gets set.
  - the host simply doesn't respond this scan (down/unreachable/timed out)
    -> we never actually checked, so the finding's lifecycle must be left
       untouched rather than falsely "resolved" (which would otherwise
       misreport as a "recurrence" the next time the host comes back with
       the same finding still present).
"""
from __future__ import annotations

import pytest

import netscan.correlate as correlate
from netscan.config import Config

HOST_KEY = "aa:bb:cc:dd:ee:ff"
CVE_ID = "CVE-2099-0001"
CPE = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"


def _host(vulnerable=True):
    """A responding host. With vulnerable=False it's still live/scanned, just
    without the service that produced the CVE finding (i.e. genuinely
    patched) -- distinct from the host not responding at all."""
    return {
        "ip": "10.0.0.5", "mac": HOST_KEY, "vendor": None, "hostname": "widget-host",
        "os_name": None, "os_accuracy": None, "device_type": None,
        "host_key": HOST_KEY,
        "services": [{
            "port": 443, "proto": "tcp", "state": "open", "service": "https",
            "product": "widget", "version": "1.0", "cpe": CPE, "cpes": [CPE],
        }] if vulnerable else [],
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

    # --- scan 2: host still responds, but the vulnerable service is gone (patched) --
    monkeypatch.setattr(correlate, "discover_and_fingerprint", lambda cfg: [_host(vulnerable=False)])
    correlate.run_scan(cfg)

    row2 = _lifecycle_row(cfg)
    assert row2 is not None
    assert row2["first_seen"] == first_seen        # unchanged
    assert row2["resolved_at"] is not None          # resolved -- host confirmed it's gone
    assert row2["recurred"] == 0

    # --- scan 3: finding reappears ------------------------------------------------
    monkeypatch.setattr(correlate, "discover_and_fingerprint", lambda cfg: [_host()])
    correlate.run_scan(cfg)

    row3 = _lifecycle_row(cfg)
    assert row3 is not None
    assert row3["first_seen"] == first_seen         # preserved across the whole run
    assert row3["resolved_at"] is None               # cleared on recurrence
    assert row3["recurred"] == 1


def test_run_scan_host_down_does_not_resolve_findings(tmp_path, monkeypatch):
    """A host that simply doesn't respond this scan must NOT have its prior
    findings marked resolved -- we never actually checked, so we don't know.
    Regression test: this used to be conflated with a genuine patch (see the
    scenario above), which meant a flaky/offline host would falsely resolve
    every one of its findings, then falsely "recur" the moment it came back
    with the same findings still present -- pure noise on the /scans trend
    view, not real remediation signal."""
    monkeypatch.setattr(correlate, "KevCatalog", _FakeKev)
    monkeypatch.setattr(correlate, "NvdClient", _FakeNvd)
    monkeypatch.setattr(correlate, "EpssClient", _FakeEpss)
    monkeypatch.setattr(correlate, "VirusTotalClient", _FakeVt)

    cfg = _make_cfg(tmp_path)

    # --- scan 1: host responds, finding present ------------------------------------
    monkeypatch.setattr(correlate, "discover_and_fingerprint", lambda cfg: [_host()])
    correlate.run_scan(cfg)
    row1 = _lifecycle_row(cfg)
    assert row1 is not None
    assert row1["resolved_at"] is None

    # --- scan 2: host doesn't respond at all (down/unreachable) --------------------
    monkeypatch.setattr(correlate, "discover_and_fingerprint", lambda cfg: [])
    correlate.run_scan(cfg)
    row2 = _lifecycle_row(cfg)
    assert row2 is not None
    assert row2["resolved_at"] is None              # untouched -- host was never checked
    assert row2["last_seen"] == row1["last_seen"]   # untouched
    assert row2["recurred"] == 0

    # --- scan 3: host responds again, finding still present ------------------------
    monkeypatch.setattr(correlate, "discover_and_fingerprint", lambda cfg: [_host()])
    correlate.run_scan(cfg)
    row3 = _lifecycle_row(cfg)
    assert row3 is not None
    assert row3["resolved_at"] is None              # never resolved, so no false "recurrence"
    assert row3["recurred"] == 0                    # critically: NOT flagged as recurring


def test_run_scan_host_down_then_return_patched_resolves(tmp_path, monkeypatch):
    """Host down in one scan must not resolve; when it returns without the
    vulnerable service, the still-open lifecycle row must resolve.

    Regression: resolving only against the immediately previous scan missed
    this case because the intervening down-scan had no finding row.
    """
    monkeypatch.setattr(correlate, "KevCatalog", _FakeKev)
    monkeypatch.setattr(correlate, "NvdClient", _FakeNvd)
    monkeypatch.setattr(correlate, "EpssClient", _FakeEpss)
    monkeypatch.setattr(correlate, "VirusTotalClient", _FakeVt)

    cfg = _make_cfg(tmp_path)

    monkeypatch.setattr(correlate, "discover_and_fingerprint", lambda cfg: [_host()])
    correlate.run_scan(cfg)
    assert _lifecycle_row(cfg)["resolved_at"] is None

    monkeypatch.setattr(correlate, "discover_and_fingerprint", lambda cfg: [])
    correlate.run_scan(cfg)
    assert _lifecycle_row(cfg)["resolved_at"] is None

    monkeypatch.setattr(
        correlate, "discover_and_fingerprint",
        lambda cfg: [_host(vulnerable=False)],
    )
    correlate.run_scan(cfg)
    row = _lifecycle_row(cfg)
    assert row is not None
    assert row["resolved_at"] is not None
    assert row["recurred"] == 0


def test_run_scan_finalizes_on_failure(tmp_path, monkeypatch):
    """A crash after create_scan must still finish the scan row and close the DB."""
    monkeypatch.setattr(correlate, "KevCatalog", _FakeKev)
    monkeypatch.setattr(correlate, "NvdClient", _FakeNvd)
    monkeypatch.setattr(correlate, "EpssClient", _FakeEpss)
    monkeypatch.setattr(correlate, "VirusTotalClient", _FakeVt)
    monkeypatch.setattr(
        correlate, "discover_and_fingerprint",
        lambda cfg: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    cfg = _make_cfg(tmp_path)
    with pytest.raises(RuntimeError, match="boom"):
        correlate.run_scan(cfg)

    from netscan.db import Database
    db = Database(cfg.db_path)
    try:
        row = db._conn.execute(
            "SELECT id, finished_at, host_count, finding_count FROM scans"
        ).fetchone()
        assert row is not None
        assert row["finished_at"] is not None
        assert row["host_count"] == 0
        assert row["finding_count"] == 0
    finally:
        db.close()
