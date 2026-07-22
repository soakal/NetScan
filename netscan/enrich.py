"""Threat-intel enrichment sources.

  * KevCatalog       — CISA Known Exploited Vulnerabilities (free JSON feed)
  * NvdClient        — NIST NVD CVE API 2.0, queried by CPE
  * VirusTotalClient — VT API v3 (optional; needs an API key)

All three cache to disk so repeated scans don't re-hammer the upstreams. NVD in
particular is rate-limited (5 req / 30s anonymous, 50 req / 30s with a free API
key from https://nvd.nist.gov/developers/request-an-api-key), so caching per-CPE
results is what makes scanning a whole subnet practical.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

import requests

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VT_API_URL = "https://www.virustotal.com/api/v3"
# EPSS: FIRST.org Exploit Prediction Scoring System. Free, no key, batchable.
EPSS_API_URL = "https://api.first.org/data/v1/epss"

USER_AGENT = "NetScan/0.1 (+internal vulnerability scanner)"


# ---------------------------------------------------------------------------
# tiny disk cache
# ---------------------------------------------------------------------------

class Cache:
    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()[:32]
        d = self.root / namespace
        d.mkdir(exist_ok=True)
        return d / f"{digest}.json"

    def get(self, namespace: str, key: str, max_age_hours: float) -> Any | None:
        p = self._path(namespace, key)
        if not p.exists():
            return None
        if (time.time() - p.stat().st_mtime) > max_age_hours * 3600:
            return None
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    def put(self, namespace: str, key: str, value: Any) -> None:
        self._path(namespace, key).write_text(json.dumps(value))


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

class KevCatalog:
    """Loads the KEV catalog and exposes a CVE-id -> entry lookup.

    Each entry carries the CISA-mandated remediation action and due date, which
    we surface directly in the report — these are the single most important
    vulnerabilities to fix because they are *known to be exploited in the wild*.
    """

    def __init__(self, cache: Cache, max_age_hours: float = 24):
        self.cache = cache
        self.max_age_hours = max_age_hours
        self._by_cve: dict[str, dict] = {}

    def load(self) -> "KevCatalog":
        data = self.cache.get("kev", "catalog", self.max_age_hours)
        if data is None:
            try:
                resp = requests.get(KEV_FEED_URL, headers={"User-Agent": USER_AGENT},
                                    timeout=30)
                resp.raise_for_status()
                data = resp.json()
                self.cache.put("kev", "catalog", data)
                print(f"[kev] loaded {data.get('count', '?')} entries (fresh)",
                      file=sys.stderr)
            except (requests.RequestException, ValueError) as e:
                print(f"[kev] failed to fetch catalog: {e}", file=sys.stderr)
                data = {"vulnerabilities": []}
        else:
            print("[kev] loaded from cache", file=sys.stderr)
        for v in data.get("vulnerabilities", []):
            self._by_cve[v["cveID"].upper()] = v
        return self

    def lookup(self, cve_id: str) -> dict | None:
        return self._by_cve.get(cve_id.upper())

    def is_kev(self, cve_id: str) -> bool:
        return cve_id.upper() in self._by_cve


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

def _version_key(v: str) -> list[tuple[int, Any]]:
    """Tokenize a version string for ordering comparison. CPE/product versions
    aren't semver (e.g. '4.6.3', '4.15.13p1', '2008r2') so we split into
    digit/alpha runs rather than assuming a fixed number of numeric fields.
    Each token is tagged (0, int) or (1, str) so digit and alpha tokens never
    get directly compared against each other (which would raise in Python 3)."""
    tokens = re.findall(r"\d+|[A-Za-z]+", v or "")
    return [(0, int(t)) if t.isdigit() else (1, t.lower()) for t in tokens]


def _compare_versions(a: str, b: str) -> int:
    ka, kb = _version_key(a), _version_key(b)
    if ka < kb:
        return -1
    if ka > kb:
        return 1
    return 0


def _matching_cpe_matches(cve: dict, cpe23: str) -> list[dict]:
    """Pull the cpeMatch entries from a raw NVD CVE record whose `criteria`
    shares the queried CPE's part:vendor:product prefix. NVD's cves/2.0
    response for a CPE query includes the *full* configurations block for
    every matched CVE, which is where the actual affected-version bounds
    live (versionStart/EndIncluding/Excluding) -- the cpeName match itself
    just means "this product appears somewhere in the config", not "this
    exact version is vulnerable"."""
    prefix = ":".join(cpe23.split(":")[:5])  # cpe:2.3:<part>:<vendor>:<product>
    out: list[dict] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable"):
                    continue
                criteria = cm.get("criteria", "")
                if not criteria.startswith(prefix + ":"):
                    continue
                fields = criteria.split(":")
                version = fields[5] if len(fields) > 5 else None
                out.append({
                    "version": version,
                    "start_incl": cm.get("versionStartIncluding"),
                    "start_excl": cm.get("versionStartExcluding"),
                    "end_incl": cm.get("versionEndIncluding"),
                    "end_excl": cm.get("versionEndExcluding"),
                })
    return out


def version_covers(detected_version: str | None, constraints: list[dict]) -> bool | None:
    """Does `detected_version` fall inside any of the affected-version
    constraints NVD reports for this CVE/CPE pairing?

    Returns True (affected), False (definitively out of range -- safe to drop
    the finding), or None (can't tell: no detected version, or NVD gave us no
    constraint data to check against -- keep the finding but flag it as
    unverified rather than silently dropping or silently trusting it).
    """
    if not detected_version or not constraints:
        return None
    for c in constraints:
        version = c.get("version")
        if version and version not in ("*", "-"):
            if _compare_versions(detected_version, version) == 0:
                return True
            continue
        ok = True
        if c.get("start_incl") and _compare_versions(detected_version, c["start_incl"]) < 0:
            ok = False
        if c.get("start_excl") and _compare_versions(detected_version, c["start_excl"]) <= 0:
            ok = False
        if c.get("end_incl") and _compare_versions(detected_version, c["end_incl"]) > 0:
            ok = False
        if c.get("end_excl") and _compare_versions(detected_version, c["end_excl"]) >= 0:
            ok = False
        if ok:
            return True
    return False


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


class NvdClient:
    def __init__(self, cache: Cache, api_key: str | None = None,
                 max_age_hours: float = 168):
        self.cache = cache
        self.api_key = api_key
        self.max_age_hours = max_age_hours
        self._last_request = 0.0
        # Be a good API citizen: anonymous = 5/30s, keyed = 50/30s.
        self._min_interval = 0.7 if api_key else 6.5

    def _throttle(self) -> None:
        delta = time.time() - self._last_request
        if delta < self._min_interval:
            time.sleep(self._min_interval - delta)
        self._last_request = time.time()

    def cves_for_cpe(self, cpe23: str) -> list[dict]:
        """Return normalized CVE findings affecting a given CPE (with version).

        Cache namespace is "nvd2" (not "nvd") because entries now carry a
        `version_constraints` field that older cached "nvd" entries don't
        have -- bumping the namespace forces a clean refetch instead of
        correlate.py silently treating old cache hits as "no constraint
        data" forever until the 168h TTL happens to expire.
        """
        cached = self.cache.get("nvd2", cpe23, self.max_age_hours)
        if cached is not None:
            return cached

        headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key
        params = {"cpeName": cpe23, "resultsPerPage": 200}

        self._throttle()
        try:
            resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=40)
            if resp.status_code == 404:
                self.cache.put("nvd2", cpe23, [])
                return []
            resp.raise_for_status()
            payload = resp.json()
        except (requests.RequestException, ValueError) as e:
            print(f"[nvd] lookup failed for {cpe23}: {e}", file=sys.stderr)
            return []  # don't cache transient failures

        findings = [self._normalize(item, cpe23) for item in payload.get("vulnerabilities", [])]
        findings = [f for f in findings if f]
        self.cache.put("nvd2", cpe23, findings)
        return findings

    def cve_by_id(self, cve_id: str) -> dict | None:
        """Fetch one CVE's NVD metadata (CVSS, CWE, summary, refs). Used for
        findings discovered by OVAL/MSRC, where we already know the CVE id."""
        cid = cve_id.upper()
        cached = self.cache.get("nvd_cve", cid, self.max_age_hours)
        if cached is not None:
            return cached or None
        headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key
        self._throttle()
        try:
            resp = requests.get(NVD_API_URL, headers=headers,
                                params={"cveId": cid}, timeout=40)
            if resp.status_code == 404:
                self.cache.put("nvd_cve", cid, {})
                return None
            resp.raise_for_status()
            items = resp.json().get("vulnerabilities", [])
        except (requests.RequestException, ValueError) as e:
            print(f"[nvd] cve lookup failed for {cid}: {e}", file=sys.stderr)
            return None
        norm = self._normalize(items[0]) if items else None
        self.cache.put("nvd_cve", cid, norm or {})
        return norm

    @staticmethod
    def _normalize(item: dict, cpe23: str | None = None) -> dict | None:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            return None
        # English description
        summary = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                summary = d.get("value", "")
                break
        # Best available CVSS base score (prefer v3.1 > v3.0 > v2)
        score, vector, version = None, None, None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cdata = metrics[key][0].get("cvssData", {})
                score = cdata.get("baseScore")
                vector = cdata.get("vectorString")
                version = cdata.get("version")
                break
        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")][:8]
        # CWE weakness ids — the taxonomy hook that lets us pivot by weakness
        # family (OWASP Top 10:2025), the way OpenHack classifies findings.
        cwes: list[str] = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.upper().startswith("CWE-") and val not in cwes:
                    cwes.append(val)
        version_constraints = _matching_cpe_matches(cve, cpe23) if cpe23 else []
        return {
            "cve_id": cve_id,
            "summary": summary,
            "cvss": score,
            "cvss_vector": vector,
            "cvss_version": version,
            "severity": _severity_from_cvss(score),
            "cwes": cwes,
            "refs": refs,
            "published": cve.get("published"),
            "version_constraints": version_constraints,
        }


# ---------------------------------------------------------------------------
# VirusTotal (optional)
# ---------------------------------------------------------------------------

class VirusTotalClient:
    def __init__(self, cache: Cache, api_key: str | None):
        self.cache = cache
        self.api_key = api_key

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict:
        return {"x-apikey": self.api_key, "User-Agent": USER_AGENT}

    def ip_reputation(self, ip: str) -> dict | None:
        """Return {'malicious': n, 'suspicious': n} for an IP, or None."""
        if not self.enabled:
            return None
        cached = self.cache.get("vt_ip", ip, max_age_hours=72)
        if cached is not None:
            return cached
        try:
            resp = requests.get(f"{VT_API_URL}/ip_addresses/{ip}",
                                headers=self._headers(), timeout=20)
            if resp.status_code == 404:
                self.cache.put("vt_ip", ip, {})
                return {}
            resp.raise_for_status()
            stats = (resp.json().get("data", {}).get("attributes", {})
                     .get("last_analysis_stats", {}))
            result = {"malicious": stats.get("malicious", 0),
                      "suspicious": stats.get("suspicious", 0)}
            self.cache.put("vt_ip", ip, result)
            return result
        except (requests.RequestException, ValueError) as e:
            print(f"[vt] ip lookup failed for {ip}: {e}", file=sys.stderr)
            return None

    def file_report(self, sha256: str) -> dict | None:
        """Look up an existing file report by hash. Does NOT upload files."""
        if not self.enabled:
            return None
        try:
            resp = requests.get(f"{VT_API_URL}/files/{sha256}",
                                headers=self._headers(), timeout=20)
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            stats = (resp.json().get("data", {}).get("attributes", {})
                     .get("last_analysis_stats", {}))
            return {"malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0)}
        except (requests.RequestException, ValueError) as e:
            print(f"[vt] file lookup failed for {sha256}: {e}", file=sys.stderr)
            return None


# ---------------------------------------------------------------------------
# EPSS (Exploit Prediction Scoring System) — FIRST.org
# ---------------------------------------------------------------------------

class EpssClient:
    """EPSS gives, per CVE, the probability it will be exploited in the wild in
    the next 30 days (0..1) plus a percentile rank. It's the single best signal
    for *prioritizing* a backlog of CVEs beyond raw CVSS: a Critical CVSS with a
    0.01 EPSS is far less urgent than a High CVSS with a 0.9 EPSS. Free, no key,
    and the endpoint accepts a comma-separated batch of CVE ids.
    """

    def __init__(self, cache: Cache, max_age_hours: float = 24):
        self.cache = cache
        self.max_age_hours = max_age_hours

    def scores_for(self, cve_ids: list[str]) -> dict[str, dict]:
        """Return {cve_id: {'epss': float, 'percentile': float}}."""
        out: dict[str, dict] = {}
        todo: list[str] = []
        for cid in {c.upper() for c in cve_ids}:
            cached = self.cache.get("epss", cid, self.max_age_hours)
            if cached is not None:
                out[cid] = cached
            else:
                todo.append(cid)

        # Batch remaining ids, ~100 per request to keep URLs sane.
        for i in range(0, len(todo), 100):
            batch = todo[i:i + 100]
            try:
                resp = requests.get(
                    EPSS_API_URL,
                    params={"cve": ",".join(batch)},
                    headers={"User-Agent": USER_AGENT},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json().get("data", [])
            except (requests.RequestException, ValueError) as e:
                print(f"[epss] lookup failed: {e}", file=sys.stderr)
                data = []
            seen = set()
            for row in data:
                cid = row.get("cve", "").upper()
                rec = {"epss": float(row.get("epss", 0) or 0),
                       "percentile": float(row.get("percentile", 0) or 0)}
                out[cid] = rec
                self.cache.put("epss", cid, rec)
                seen.add(cid)
            # CVEs EPSS has no score for (cache empty so we don't refetch).
            for cid in batch:
                if cid not in seen:
                    rec = {"epss": 0.0, "percentile": 0.0}
                    out[cid] = rec
                    self.cache.put("epss", cid, rec)
        return out
