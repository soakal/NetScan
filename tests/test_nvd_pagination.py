"""NVD CPE lookup pagination."""
from __future__ import annotations

import pytest
import requests

from netscan.enrich import Cache, NvdClient, NvdLookupError


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


def test_later_page_failure_is_not_treated_as_empty_or_cached(tmp_path, monkeypatch):
    cache = Cache(str(tmp_path / "cache"))
    client = NvdClient(cache, api_key=None, max_age_hours=24)
    monkeypatch.setattr(client, "_throttle", lambda: None)
    cpe = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"
    calls = []

    def fake_get(url, headers=None, params=None, timeout=None):
        start = int(params["startIndex"])
        calls.append(start)
        if start == 0:
            batch = [{"cve": {"id": f"CVE-2099-{i:04d}"}} for i in range(200)]
            return _Resp(200, {"totalResults": 350, "vulnerabilities": batch})
        raise requests.ConnectionError("second page unavailable")

    monkeypatch.setattr("netscan.enrich.requests.get", fake_get)

    with pytest.raises(NvdLookupError, match="incomplete NVD lookup"):
        client.cves_for_cpe(cpe)
    assert calls == [0, 200]
    assert cache.get("nvd", cpe, 24) is None


@pytest.mark.parametrize("failure_kind", ["404", "empty"])
def test_incomplete_later_page_never_caches_partial_results(
        tmp_path, monkeypatch, failure_kind):
    cache = Cache(str(tmp_path / "cache"))
    client = NvdClient(cache, api_key=None, max_age_hours=24)
    monkeypatch.setattr(client, "_throttle", lambda: None)
    cpe = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"

    def fake_get(url, headers=None, params=None, timeout=None):
        start = int(params["startIndex"])
        if start == 0:
            batch = [{"cve": {"id": f"CVE-2099-{i:04d}"}} for i in range(200)]
            return _Resp(200, {"totalResults": 350, "vulnerabilities": batch})
        if failure_kind == "404":
            return _Resp(404, {})
        return _Resp(200, {"totalResults": 350, "vulnerabilities": []})

    monkeypatch.setattr("netscan.enrich.requests.get", fake_get)

    with pytest.raises(NvdLookupError):
        client.cves_for_cpe(cpe)
    assert cache.get("nvd", cpe, 24) is None
