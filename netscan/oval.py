"""OVAL-based Linux package matching.

The accurate way to assess a Linux host is *not* to map a package version to a
generic CPE and ask NVD — distros backport security fixes, so the upstream
version looks "old" while actually being patched. Instead, distros publish OVAL
(Open Vulnerability and Assessment Language) feeds that say, authoritatively:
"on <release>, package <name> is vulnerable to <CVE> until version <fixed>."

This module downloads a distro's OVAL feed, parses it into
{package_name: [(cve, fixed_evr, severity), ...]}, and compares each installed
package against the fixed version using the distro's real version-ordering rules
(dpkg for Debian/Ubuntu, rpm for the RHEL family). A package is vulnerable iff
its installed version is strictly older than the fixed version.

Network access is import-guarded/cached; all parsing and version comparison are
pure functions so they can be unit-tested without fetching multi-MB feeds.
"""
from __future__ import annotations

import bz2
import gzip
import re
import sys
import xml.etree.ElementTree as ET

import requests

from .enrich import Cache

USER_AGENT = "NetScan/0.1 (+internal vulnerability scanner)"

# Distro id (from /etc/os-release ID) -> feed descriptor.
#   family: "dpkg" or "rpm" (selects the version comparator + test type)
#   url:    {release} is substituted with VERSION_ID / codename as needed
# These are the canonical, free OVAL endpoints. Some distros key the feed by
# codename rather than number; resolve_release() handles the common cases.
OVAL_SOURCES = {
    "ubuntu": {"family": "dpkg",
               "url": "https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.usn.oval.xml.bz2"},
    "debian": {"family": "dpkg",
               "url": "https://www.debian.org/security/oval/oval-definitions-{codename}.xml"},
    "rhel":   {"family": "rpm",
               "url": "https://www.redhat.com/security/data/oval/v2/RHEL{major}/rhel-{major}.oval.xml.bz2"},
    "centos": {"family": "rpm",
               "url": "https://www.redhat.com/security/data/oval/v2/RHEL{major}/rhel-{major}.oval.xml.bz2"},
    "rocky":  {"family": "rpm",
               "url": "https://www.redhat.com/security/data/oval/v2/RHEL{major}/rhel-{major}.oval.xml.bz2"},
    "almalinux": {"family": "rpm",
               "url": "https://www.redhat.com/security/data/oval/v2/RHEL{major}/rhel-{major}.oval.xml.bz2"},
}

UBUNTU_CODENAMES = {
    "18.04": "bionic", "20.04": "focal", "22.04": "jammy",
    "24.04": "noble", "23.10": "mantic",
}
DEBIAN_CODENAMES = {"10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie"}


def family_for(distro_id: str) -> str | None:
    src = OVAL_SOURCES.get((distro_id or "").lower())
    return src["family"] if src else None


def _feed_url(distro_id: str, version_id: str) -> str | None:
    d = (distro_id or "").lower()
    src = OVAL_SOURCES.get(d)
    if not src:
        return None
    major = (version_id or "").split(".")[0]
    codename = None
    if d == "ubuntu":
        codename = UBUNTU_CODENAMES.get(version_id, version_id)
    elif d == "debian":
        codename = DEBIAN_CODENAMES.get(major, major)
    return src["url"].format(codename=codename, major=major, release=version_id)


# ---------------------------------------------------------------------------
# Debian (dpkg) version comparison  — per deb-version(5)
# ---------------------------------------------------------------------------

def _dpkg_charval(ch: str | None) -> int:
    # Ordering within a non-digit run: '~' < end-of-string < letters < symbols.
    if ch is None:
        return 0           # end of string
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)     # letters: 65..122 (all > 0, so after end-of-string)
    return ord(ch) + 256   # other symbols sort after letters


def _dpkg_cmp_part(a: str, b: str) -> int:
    ia = ib = 0
    while ia < len(a) or ib < len(b):
        # --- non-digit run, modified lexical order ---
        while (ia < len(a) and not a[ia].isdigit()) or (ib < len(b) and not b[ib].isdigit()):
            ca = _dpkg_charval(a[ia]) if (ia < len(a) and not a[ia].isdigit()) else 0
            cb = _dpkg_charval(b[ib]) if (ib < len(b) and not b[ib].isdigit()) else 0
            if ca != cb:
                return -1 if ca < cb else 1
            if ia < len(a) and not a[ia].isdigit():
                ia += 1
            if ib < len(b) and not b[ib].isdigit():
                ib += 1
        # --- digit run, numeric (leading zeros ignored) ---
        na = ""
        while ia < len(a) and a[ia].isdigit():
            na += a[ia]; ia += 1
        nb = ""
        while ib < len(b) and b[ib].isdigit():
            nb += b[ib]; ib += 1
        va, vb = int(na or "0"), int(nb or "0")
        if va != vb:
            return -1 if va < vb else 1
    return 0


def _split_deb(v: str):
    epoch, _, rest = v.partition(":") if ":" in v else ("0", ":", v)
    if not epoch.isdigit():
        epoch, rest = "0", v
    if "-" in rest:
        upstream, _, revision = rest.rpartition("-")
    else:
        upstream, revision = rest, "0"
    return int(epoch), upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _split_deb(a)
    eb, ub, rb = _split_deb(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _dpkg_cmp_part(ua, ub)
    if c:
        return c
    return _dpkg_cmp_part(ra, rb)


# ---------------------------------------------------------------------------
# RPM version comparison  — rpmvercmp
# ---------------------------------------------------------------------------

def _rpm_segments(s: str):
    # yields (is_num, value) segments; '~' and '^' handled by caller
    return re.findall(r"(\d+|[a-zA-Z]+|~|\^)", s)


def _rpm_cmp_str(a: str, b: str) -> int:
    sa, sb = _rpm_segments(a), _rpm_segments(b)
    i = 0
    while i < len(sa) and i < len(sb):
        x, y = sa[i], sb[i]
        # tilde: older
        if x == "~" or y == "~":
            if x != "~":
                return 1
            if y != "~":
                return -1
            i += 1; continue
        if x == "^" or y == "^":
            if x != "^":
                return -1
            if y != "^":
                return 1
            i += 1; continue
        xnum, ynum = x.isdigit(), y.isdigit()
        if xnum and ynum:
            xv, yv = int(x), int(y)
            if xv != yv:
                return -1 if xv < yv else 1
        elif xnum != ynum:
            return 1 if xnum else -1  # numeric segment newer than alpha
        else:
            if x != y:
                return -1 if x < y else 1
        i += 1
    if len(sa) == len(sb):
        return 0
    # One side has trailing segments. A leading '~' there makes that side OLDER;
    # otherwise (including '^') the longer side is NEWER.
    rem = sa[i] if i < len(sa) else sb[i]
    longer_is_a = i < len(sa)
    if rem == "~":
        return -1 if longer_is_a else 1
    return 1 if longer_is_a else -1


def _split_rpm(evr: str):
    epoch, _, rest = evr.partition(":") if ":" in evr else ("0", ":", evr)
    if not epoch.isdigit():
        epoch, rest = "0", evr
    if "-" in rest:
        ver, _, rel = rest.rpartition("-")
    else:
        ver, rel = rest, ""
    return int(epoch), ver, rel


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = _split_rpm(a)
    eb, vb, rb = _split_rpm(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _rpm_cmp_str(va, vb)
    if c:
        return c
    if ra and rb:
        return _rpm_cmp_str(ra, rb)
    return 0


def version_less_than(family: str, installed: str, fixed: str) -> bool:
    cmp = dpkg_compare if family == "dpkg" else rpm_compare
    return cmp(installed, fixed) < 0


# ---------------------------------------------------------------------------
# OVAL parsing (stdlib ElementTree; namespace-agnostic by local tag name)
# ---------------------------------------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_oval(xml_text: str) -> dict[str, list[tuple[str, str, str]]]:
    """Parse OVAL XML into {package_name: [(cve_id, fixed_evr, severity), ...]}.

    Handles the dpkginfo (Debian/Ubuntu) and rpminfo (RHEL family) test shapes,
    which are structurally identical: definition -> CVE refs + criteria; criteria
    reference tests; a test references an object (package name) and a state
    (fixed evr with operation 'less than')."""
    root = ET.fromstring(xml_text)

    tests: dict[str, tuple[str | None, str | None]] = {}
    objects: dict[str, str] = {}
    states: dict[str, tuple[str, str]] = {}
    definitions = []

    for el in root.iter():
        name = _local(el.tag)
        if name.endswith("_test"):
            oid = sid = None
            for ch in el:
                ln = _local(ch.tag)
                if ln == "object":
                    oid = ch.get("object_ref")
                elif ln == "state":
                    sid = ch.get("state_ref")
            tests[el.get("id")] = (oid, sid)
        elif name.endswith("_object"):
            pkgname = None
            for ch in el:
                if _local(ch.tag) == "name":
                    pkgname = (ch.text or "").strip()
            if pkgname:
                objects[el.get("id")] = pkgname
        elif name.endswith("_state"):
            evr = None
            op = ""
            for ch in el:
                if _local(ch.tag) == "evr":
                    evr = (ch.text or "").strip()
                    op = ch.get("operation", "")
            if evr:
                states[el.get("id")] = (evr, op)
        elif name == "definition":
            definitions.append(el)

    out: dict[str, list[tuple[str, str, str]]] = {}
    for d in definitions:
        cves: list[str] = []
        severity = ""
        test_refs: list[str] = []
        for el in d.iter():
            ln = _local(el.tag)
            if ln == "reference" and (el.get("source") or "").upper() == "CVE":
                rid = el.get("ref_id")
                if rid:
                    cves.append(rid)
            elif ln == "severity" and el.text:
                severity = el.text.strip()
            elif ln == "criterion" and el.get("test_ref"):
                test_refs.append(el.get("test_ref"))
        if not cves:
            continue
        for tref in test_refs:
            oid, sid = tests.get(tref, (None, None))
            if not oid or not sid:
                continue
            pkg = objects.get(oid)
            st = states.get(sid)
            if not pkg or not st:
                continue
            evr, op = st
            # We only care about the "patched in version X" assertion.
            if "less than" not in op.lower():
                continue
            for cve in cves:
                out.setdefault(pkg, []).append((cve, evr, severity))
    return out


# ---------------------------------------------------------------------------
# feed loading (cached) + matching
# ---------------------------------------------------------------------------

def _decompress(url: str, content: bytes) -> str:
    if url.endswith(".bz2"):
        return bz2.decompress(content).decode("utf-8", "replace")
    if url.endswith(".gz"):
        return gzip.decompress(content).decode("utf-8", "replace")
    return content.decode("utf-8", "replace")


def load_feed(distro_id: str, version_id: str, cache: Cache,
              max_age_hours: float = 168) -> dict | None:
    url = _feed_url(distro_id, version_id)
    if not url:
        return None
    key = url
    cached = cache.get("oval", key, max_age_hours)
    if cached is not None:
        return cached
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=120)
        resp.raise_for_status()
        xml_text = _decompress(url, resp.content)
        parsed = parse_oval(xml_text)
    except (requests.RequestException, ValueError, OSError, ET.ParseError) as e:
        print(f"[oval] feed load failed for {distro_id} {version_id}: {e}",
              file=sys.stderr)
        return None
    cache.put("oval", key, parsed)
    print(f"[oval] {distro_id} {version_id}: {len(parsed)} package definitions",
          file=sys.stderr)
    return parsed


def match_packages(parsed: dict, packages: list[dict], family: str) -> list[dict]:
    """Return findings: installed packages older than their fixed version.

    Each finding: {cve_id, package, installed_version, fixed_version, severity}.
    """
    findings = []
    seen = set()
    for pkg in packages:
        name = pkg.get("name") or pkg.get("service")
        inst = pkg.get("version")
        if not name or not inst or name not in parsed:
            continue
        for cve, fixed, severity in parsed[name]:
            if version_less_than(family, inst, fixed):
                k = (name, cve)
                if k in seen:
                    continue
                seen.add(k)
                findings.append({
                    "cve_id": cve, "package": name,
                    "installed_version": inst, "fixed_version": fixed,
                    "severity_hint": severity,
                })
    return findings
