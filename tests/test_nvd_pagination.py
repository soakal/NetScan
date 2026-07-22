"""NVD CPE lookup pagination."""
from __future__ import annotations

from netscan.enrich import Cache, NvdClient


class _Resp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_cves_for_cpe_paginates(tmp_path, monkeypatch):
    cache = Cache(str(tmp_path / "cache"))
    client = NvdClient(cache, api_key=None, max_age_hours=24)
    # Skip throttle sleeps in tests.
    monkeypatch.setattr(client, "_throttle", lambda: None)

    cpe = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"
    calls = []

    def fake_get(url, headers=None, params=None, timeout=None):
        calls.append(dict(params))
        start = int(params["startIndex"])
        # Two pages of 200, totalResults=350.
        if start == 0:
            batch = [{"cve": {"id": f"CVE-2099-{i:04d}", "descriptions": [
                {"lang": "en", "value": f"desc {i}"}]}} for i in range(200)]
            return _Resp(200, {"totalResults": 350, "vulnerabilities": batch})
        if start == 200:
            batch = [{"cve": {"id": f"CVE-2099-{i:04d}", "descriptions": [
                {"lang": "en", "value": f"desc {i}"}]}} for i in range(200, 350)]
            return _Resp(200, {"totalResults": 350, "vulnerabilities": batch})
        raise AssertionError(f"unexpected startIndex {start}")

    monkeypatch.setattr("netscan.enrich.requests.get", fake_get)

    findings = client.cves_for_cpe(cpe)
    assert len(findings) == 350
    assert findings[0]["cve_id"] == "CVE-2099-0000"
    assert findings[-1]["cve_id"] == "CVE-2099-0349"
    assert [c["startIndex"] for c in calls] == [0, 200]

    # Second call hits cache — no more HTTP.
    calls.clear()
    again = client.cves_for_cpe(cpe)
    assert len(again) == 350
    assert calls == []
