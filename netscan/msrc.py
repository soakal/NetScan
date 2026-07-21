"""MSRC (Microsoft Security Response Center) CVE -> KB correlation for Windows.

Credentialed Windows scanning gives us the installed hotfix (KB) list. MSRC
publishes monthly CVRF documents that say which KB fixes which CVE for which
product. Combining the two lets us turn "here are the installed KBs" into the
actually-useful "here are the CVEs you're *missing* the patch for".

Two wrinkles this handles:
  * Product matching — a host's OS caption is matched to MSRC product entries by
    normalized substring (e.g. "windows server 2019", "windows 11").
  * Supersedence — Windows cumulative updates supersede earlier ones, so a CVE
    can be fixed even if its *original* KB isn't installed, as long as a KB that
    supersedes it is. We build the supersedence graph from the CVRF and expand
    the installed set transitively before deciding "missing".

The CVRF fetch is cached and import-guarded; parse_cvrf() and correlate() are
pure and unit-tested with sample documents. The MSRC v3.0 API is free and needs
no key (an optional key is supported for higher limits).
"""
from __future__ import annotations

import re
import sys
from datetime import date

import requests

from .enrich import Cache

MSRC_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"
USER_AGENT = "NetScan/0.1 (+internal vulnerability scanner)"
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

REMEDIATION_VENDOR_FIX = 2   # CVRF RemediationType: 2 = Vendor Fix
THREAT_SEVERITY = 3          # CVRF ThreatType: 3 = Severity


def _kb_digits(s: str) -> list[str]:
    """Extract KB numbers (digit groups, 5-8 digits) from a string."""
    return re.findall(r"\d{5,8}", s or "")


def normalize_kb(kb: str) -> str:
    m = re.search(r"\d{5,8}", kb or "")
    return m.group(0) if m else (kb or "").strip()


def recent_month_ids(n: int, today: date | None = None) -> list[str]:
    today = today or date.today()
    y, m = today.year, today.month
    out = []
    for _ in range(n):
        out.append(f"{y}-{_MONTHS[m-1]}")
        m -= 1
        if m == 0:
            m = 12; y -= 1
    return out


# Host OS caption -> normalized product keys used for substring matching.
def product_keys_for(os_caption: str) -> list[str]:
    c = (os_caption or "").lower()
    keys = []
    for needle in ("windows server 2022", "windows server 2019",
                   "windows server 2016", "windows server 2012",
                   "windows 11", "windows 10"):
        if needle in c:
            keys.append(needle)
    if not keys and "windows server" in c:
        keys.append("windows server")
    return keys


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

def parse_cvrf(doc: dict) -> dict:
    """Parse one CVRF JSON document into a normalized structure:

      {
        "products": {product_id: name},
        "supersedes": {kb: set(superseded_kbs)},
        "vulns": [ {cve, title, cvss:{score, product_ids},
                    severity:{value, product_ids},
                    fixes:[{kb, product_ids, supersedes:[kb,...]}] } ]
      }
    """
    products = {}
    for fp in (doc.get("ProductTree", {}) or {}).get("FullProductName", []) or []:
        pid = fp.get("ProductID")
        if pid:
            products[pid] = fp.get("Value", "")

    supersedes: dict[str, set] = {}
    vulns = []
    for v in doc.get("Vulnerability", []) or []:
        cve = v.get("CVE")
        if not cve:
            continue
        title = (v.get("Title") or {}).get("Value", "")

        cvss = None
        for sset in v.get("CVSSScoreSets", []) or []:
            score = sset.get("BaseScore")
            if score is not None:
                cvss = {"score": score, "product_ids": sset.get("ProductID", []) or []}
                break

        severity = None
        for t in v.get("Threats", []) or []:
            if t.get("Type") == THREAT_SEVERITY:
                severity = {"value": (t.get("Description") or {}).get("Value", ""),
                            "product_ids": t.get("ProductID", []) or []}
                break

        fixes = []
        for rem in v.get("Remediations", []) or []:
            if rem.get("Type") != REMEDIATION_VENDOR_FIX:
                continue
            kbs = _kb_digits((rem.get("Description") or {}).get("Value", ""))
            if not kbs:
                continue
            kb = kbs[0]
            sup = _kb_digits(rem.get("Supercedence", "") or "")
            if sup:
                supersedes.setdefault(kb, set()).update(sup)
            fixes.append({"kb": kb,
                          "product_ids": rem.get("ProductID", []) or [],
                          "supersedes": sup})
        if fixes:
            vulns.append({"cve": cve, "title": title, "cvss": cvss,
                          "severity": severity, "fixes": fixes})

    return {"products": products, "supersedes": supersedes, "vulns": vulns}


def merge_parsed(docs: list[dict]) -> dict:
    out = {"products": {}, "supersedes": {}, "vulns": []}
    for d in docs:
        out["products"].update(d.get("products", {}))
        for kb, sup in d.get("supersedes", {}).items():
            out["supersedes"].setdefault(kb, set()).update(sup)
        out["vulns"].extend(d.get("vulns", []))
    return out


# ---------------------------------------------------------------------------
# correlation
# ---------------------------------------------------------------------------

def _expand_installed(installed: set[str], supersedes: dict[str, set]) -> set[str]:
    """An installed KB 'covers' every KB it supersedes, transitively."""
    covered = set(installed)
    stack = list(installed)
    while stack:
        kb = stack.pop()
        for sub in supersedes.get(kb, ()): 
            if sub not in covered:
                covered.add(sub)
                stack.append(sub)
    return covered


def correlate(parsed: dict, host_product_keys: list[str],
              installed_kbs: list[str]) -> dict:
    """Return {'missing': [...], 'patched': [...]} for a host.

    A vuln is considered for this host only if it has a vendor-fix KB tied to a
    product whose name matches one of host_product_keys.
    """
    products = parsed.get("products", {})
    supersedes = parsed.get("supersedes", {})

    # product ids whose name matches the host
    host_pids = {pid for pid, name in products.items()
                 if any(k in (name or "").lower() for k in host_product_keys)}

    installed = {normalize_kb(k) for k in installed_kbs}
    covered = _expand_installed(installed, supersedes)

    missing, patched = [], []
    for v in parsed.get("vulns", []):
        # Keep fixes that apply to this host's product(s). If we couldn't match
        # the host to any product id, be permissive and consider all fixes.
        if host_pids:
            host_fixes = [f for f in v["fixes"] if set(f["product_ids"]) & host_pids]
        else:
            host_fixes = list(v["fixes"])
        if not host_fixes:
            continue
        fixing_kbs = {f["kb"] for f in host_fixes}
        cvss = (v.get("cvss") or {}).get("score")
        sev = (v.get("severity") or {}).get("value")
        entry = {"cve_id": v["cve"], "title": v["title"],
                 "kb": sorted(fixing_kbs), "cvss_hint": cvss, "severity_hint": sev}
        if fixing_kbs & covered:
            patched.append(entry)
        else:
            missing.append(entry)
    return {"missing": missing, "patched": patched}


# ---------------------------------------------------------------------------
# fetch (cached)
# ---------------------------------------------------------------------------

class MsrcClient:
    def __init__(self, cache: Cache, api_key: str | None = None,
                 max_age_hours: float = 168):
        self.cache = cache
        self.api_key = api_key
        self.max_age_hours = max_age_hours

    def fetch_month(self, month_id: str) -> dict | None:
        cached = self.cache.get("msrc", month_id, self.max_age_hours)
        if cached is not None:
            return cached or None
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.api_key:
            headers["api-key"] = self.api_key
        try:
            resp = requests.get(f"{MSRC_BASE}/{month_id}", headers=headers, timeout=60)
            if resp.status_code == 404:
                self.cache.put("msrc", month_id, {})
                return None
            resp.raise_for_status()
            parsed = parse_cvrf(resp.json())
        except (requests.RequestException, ValueError) as e:
            print(f"[msrc] fetch failed for {month_id}: {e}", file=sys.stderr)
            return None
        # sets aren't JSON-serializable; store supersedes as lists
        serializable = {**parsed,
                        "supersedes": {k: sorted(s) for k, s in parsed["supersedes"].items()}}
        self.cache.put("msrc", month_id, serializable)
        print(f"[msrc] {month_id}: {len(parsed['vulns'])} fixable vulns", file=sys.stderr)
        return parsed

    def load_recent(self, months: int) -> dict:
        docs = []
        for mid in recent_month_ids(months):
            d = self.fetch_month(mid)
            if d:
                # normalize supersedes back to sets if loaded from cache
                d["supersedes"] = {k: set(v) for k, v in d.get("supersedes", {}).items()}
                docs.append(d)
        return merge_parsed(docs)
