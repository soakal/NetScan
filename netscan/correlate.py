"""Orchestrates a full scan:

    discover/fingerprint
      -> correlate CPEs to CVEs (NVD) + KEV flag
      -> classify by CWE / OWASP Top 10:2025 family (OpenHack-style taxonomy)
      -> score exploit likelihood (EPSS)
      -> blend into a priority score
      -> generate remediation + firmware advice
      -> persist + diff against the previous scan for patch verification.

Findings are collected in memory first so EPSS can be fetched for all CVEs in a
single batched call, then enriched and written.
"""
from __future__ import annotations

import sys
import time

from .config import Config
from .db import Database
from .enrich import Cache, EpssClient, KevCatalog, NvdClient, VirusTotalClient
from .firmware import check_firmware
from .remediation import steps_for
from .scanner import _expand_targets, discover_and_fingerprint
from .taxonomy import cwe_name, owasp_family_for

_SEV_WEIGHT = {"Critical": 40, "High": 20, "Medium": 8, "Low": 2,
               "None": 0, "Unknown": 1}
_KEV_MULTIPLIER = 2.5


def _sev_from_hint(hint: str | None) -> str | None:
    return {"critical": "Critical", "important": "High", "high": "High",
            "moderate": "Medium", "medium": "Medium", "low": "Low"}.get(
        (hint or "").lower())


def _cred_finding(nvd, kev, cve_id, *, service, product, version, source,
                  port=0, severity_hint=None, cvss_hint=None, lead_steps=None):
    """Build a finding for a CVE discovered by OVAL/MSRC (we already know the
    CVE id; enrich CVSS/CWE/summary from NVD, flag KEV)."""
    meta = nvd.cve_by_id(cve_id) or {}
    cvss = meta.get("cvss") if meta.get("cvss") is not None else cvss_hint
    severity = meta.get("severity")
    if not severity or severity in ("Unknown", "None"):
        severity = _sev_from_hint(severity_hint) or severity or "Unknown"
    primary_cwe = (meta.get("cwes") or [None])[0]
    okey, oname = owasp_family_for(primary_cwe)
    kev_entry = kev.lookup(cve_id)
    return {
        "cve_id": cve_id, "port": port, "service": service,
        "product": product, "version": version, "cpe": None,
        "cvss": cvss, "severity": severity,
        "is_kev": bool(kev_entry),
        "ransomware": bool(kev_entry and str(
            kev_entry.get("knownRansomwareCampaignUse", "")).lower() == "known"),
        "cwe": primary_cwe,
        "cwe_name": cwe_name(primary_cwe) if primary_cwe else None,
        "owasp_key": okey, "owasp_name": oname,
        "summary": meta.get("summary"), "refs": meta.get("refs", []),
        "source": source, "_kev_entry": kev_entry, "_lead_steps": lead_steps or [],
    }


def _priority(f: dict) -> float:
    """Blended urgency: CVSS severity + exploit likelihood (EPSS) + KEV/ransom.

    This is the OpenHack-flavored bit: don't just rank by CVSS, rank by how
    likely the thing is to actually be used against you.
    """
    cvss = f.get("cvss") or 0.0
    epss = f.get("epss") or 0.0
    score = cvss * 10.0          # 0..100
    score += epss * 60.0         # 0..60
    if f.get("is_kev"):
        score += 40.0
    if f.get("ransomware"):
        score += 20.0
    return round(score, 1)


def _risk_score(findings: list[dict]) -> float:
    score = 0.0
    for f in findings:
        w = _SEV_WEIGHT.get(f.get("severity", "Unknown"), 1)
        if f.get("is_kev"):
            w *= _KEV_MULTIPLIER
        w *= (1.0 + (f.get("epss") or 0.0))  # exploit likelihood up to ~2x
        score += w
    return round(score, 1)


def run_scan(cfg: Config) -> int:
    if not cfg.targets:
        raise ValueError("No targets configured. Set `targets:` in your config.")

    db = Database(cfg.db_path)
    cache = Cache(cfg.cache_dir)
    kev = KevCatalog(cache, cfg.kev_cache_hours).load()
    nvd = NvdClient(cache, cfg.nvd_api_key, cfg.nvd_cache_hours)
    epss = EpssClient(cache, cfg.kev_cache_hours)
    vt = VirusTotalClient(cache, cfg.vt_api_key)

    scan_id = db.create_scan(cfg.scan_profile, cfg.targets)
    prev_scan_id = db.previous_scan_id(scan_id)
    prior_keys = db.prior_findings_keys(prev_scan_id) if prev_scan_id else set()
    prior_full = db.prior_findings_full(prev_scan_id) if prev_scan_id else {}

    print(f"[scan #{scan_id}] starting ({cfg.scan_profile} profile)", file=sys.stderr)
    hosts = discover_and_fingerprint(cfg)
    print(f"[scan #{scan_id}] {len(hosts)} live host(s) found", file=sys.stderr)

    if cfg.credentialed and cfg.credentials:
        from . import credentialed as cred_mod
        print(f"[scan #{scan_id}] credentialed scanning enabled "
              f"({cred_mod.deps_status()})", file=sys.stderr)

    # Load MSRC CVE->KB data once (recent patch-Tuesday months) if any WinRM
    # credential could apply. Cached; empty if offline (we just skip MSRC then).
    msrc_data = None
    if cfg.credentialed and cfg.msrc_matching and \
            any(c.type == "winrm" for c in cfg.credentials):
        from .msrc import MsrcClient
        msrc_data = MsrcClient(cache, cfg.msrc_api_key, cfg.nvd_cache_hours)\
            .load_recent(cfg.msrc_months)
        print(f"[scan #{scan_id}] MSRC: {len(msrc_data.get('vulns', []))} "
              f"fixable vulns across {cfg.msrc_months} month(s)", file=sys.stderr)

    # ---- Phase 1: correlate CVEs per host (in memory) --------------------
    current_keys: set[tuple[str, str, int]] = set()
    per_host: list[dict] = []

    for host in hosts:
        host_key = host["host_key"]
        host["auth_method"] = "network"
        cred_payload = None

        # Credentialed enrichment: log in (read-only) and read real inventory.
        if cfg.credentialed and cfg.credentials:
            cred = cred_mod.credential_for(host, cfg.credentials)
            if cred:
                res = cred_mod.scan_host(host, cred)
                if res.ok:
                    cred_payload = res
                    host["auth_method"] = res.auth_method
                    if res.os_name:
                        host["os_name"] = res.os_name
                    if res.os_build:
                        host["os_build"] = res.os_build
                    # OS CPE -> pseudo-service so OS-level CVEs are correlated.
                    if res.os_cpe:
                        host.setdefault("services", []).append({
                            "port": 0, "proto": "os", "state": "info",
                            "service": "operating-system",
                            "product": res.os_name, "version": res.os_build,
                            "cpe": res.os_cpe, "cpes": [res.os_cpe],
                            "source": res.auth_method,
                        })
                    # Confidently-mapped packages -> pseudo-services (correlated);
                    # all packages stored for inventory regardless of CPE.
                    for pkg in res.packages:
                        host.setdefault("services", []).append({
                            "port": 0, "proto": "pkg", "state": "installed",
                            "service": pkg["name"], "product": pkg["name"],
                            "version": pkg.get("version"),
                            "cpe": pkg.get("cpe"),
                            "cpes": [pkg["cpe"]] if pkg.get("cpe") else [],
                            "source": res.auth_method,
                        })
                    print(f"[cred] {host['ip']} via {res.auth_method}: "
                          f"{len(res.packages)} pkgs, {len(res.hotfixes)} hotfixes",
                          file=sys.stderr)
                else:
                    print(f"[cred] {host['ip']}: {res.error}", file=sys.stderr)

        vt_malicious = 0
        if vt.enabled and cfg.vt_check_host_ips:
            rep = vt.ip_reputation(host["ip"])
            if rep:
                vt_malicious = rep.get("malicious", 0)
        host["vt_malicious"] = vt_malicious

        host_id = db.add_host(scan_id, host)

        # Persist credentialed facts (hotfixes, kernel, counts).
        if cred_payload:
            for kb in cred_payload.hotfixes:
                db.add_fact(host_id, "hotfix", kb)
            if cred_payload.kernel:
                db.add_fact(host_id, "kernel", cred_payload.kernel)
            db.add_fact(host_id, "package_count", str(len(cred_payload.packages)))

        findings = []
        device_cves = []
        authoritative = False  # an OVAL/MSRC backend handled this host's inventory

        def _add(f):
            key = (host_key, f["cve_id"], f.get("port") or 0)
            if key in current_keys:
                return
            current_keys.add(key)
            findings.append(f)
            device_cves.append(f["cve_id"])

        # OVAL (Linux): backport-aware package matching against the distro feed.
        if cred_payload and cred_payload.auth_method == "ssh" and cfg.oval_matching:
            from . import oval
            fam = oval.family_for(cred_payload.distro_id)
            if fam:
                parsed = oval.load_feed(cred_payload.distro_id,
                                        cred_payload.version_id, cache,
                                        cfg.nvd_cache_hours)
                if parsed:
                    authoritative = True
                    pkgs = [{"name": p["name"], "version": p.get("version")}
                            for p in cred_payload.packages]
                    for m in oval.match_packages(parsed, pkgs, fam):
                        lead = [
                            f"Upgrade {m['package']} to {m['fixed_version']} or "
                            f"later (installed {m['installed_version']}). The distro "
                            f"ships a fixed build — `apt`/`dnf` update and restart "
                            f"affected services."]
                        _add(_cred_finding(
                            nvd, kev, m["cve_id"], service=m["package"],
                            product=m["package"], version=m["installed_version"],
                            source="oval", severity_hint=m["severity_hint"],
                            lead_steps=lead))
                    print(f"[oval] {host['ip']}: {len(findings)} package finding(s)",
                          file=sys.stderr)

        # MSRC (Windows): missing-patch detection from installed KBs.
        if cred_payload and cred_payload.auth_method == "winrm" and msrc_data:
            from . import msrc as msrc_mod
            keys = msrc_mod.product_keys_for(cred_payload.os_name or "")
            mres = msrc_mod.correlate(msrc_data, keys, cred_payload.hotfixes)
            authoritative = True
            for m in mres["missing"]:
                kb = (m["kb"] or ["?"])[0]
                lead = [
                    f"Install Microsoft update KB{kb} (or a newer cumulative "
                    f"update that supersedes it).",
                    "Deploy via WSUS / Intune / SCCM and reboot if required.",
                    "Re-run the scan — the finding clears once a covering KB is "
                    "present in Get-HotFix."]
                _add(_cred_finding(
                    nvd, kev, m["cve_id"], service=f"KB{kb}", product="Microsoft",
                    version=None, source="msrc", severity_hint=m["severity_hint"],
                    cvss_hint=m["cvss_hint"], lead_steps=lead))
            db.add_fact(host_id, "msrc_patched", str(len(mres["patched"])))
            db.add_fact(host_id, "msrc_missing", str(len(mres["missing"])))
            print(f"[msrc] {host['ip']}: {len(mres['missing'])} missing, "
                  f"{len(mres['patched'])} already patched", file=sys.stderr)

        for svc in host.get("services", []):
            db.add_service(host_id, svc)
            # When an authoritative backend handled this host, don't also do
            # imprecise CPE matching on the OS / installed packages (that's the
            # false-positive path OVAL/MSRC exist to replace). Real listening
            # network services are still correlated by CPE.
            if authoritative and svc.get("proto") in ("pkg", "os"):
                continue
            for cpe in svc.get("cpes") or ([svc["cpe"]] if svc.get("cpe") else []):
                if not cpe:
                    continue
                for cve in nvd.cves_for_cpe(cpe):
                    key = (host_key, cve["cve_id"], svc.get("port") or 0)
                    if key in current_keys:
                        continue
                    current_keys.add(key)
                    kev_entry = kev.lookup(cve["cve_id"])
                    primary_cwe = (cve.get("cwes") or [None])[0]
                    okey, oname = owasp_family_for(primary_cwe)
                    f = {
                        "cve_id": cve["cve_id"],
                        "port": svc.get("port"),
                        "service": svc.get("service"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "cpe": cpe,
                        "cvss": cve.get("cvss"),
                        "severity": cve.get("severity"),
                        "is_kev": bool(kev_entry),
                        "ransomware": bool(kev_entry and str(
                            kev_entry.get("knownRansomwareCampaignUse", "")
                        ).lower() == "known"),
                        "cwe": primary_cwe,
                        "cwe_name": cwe_name(primary_cwe) if primary_cwe else None,
                        "owasp_key": okey,
                        "owasp_name": oname,
                        "summary": cve.get("summary"),
                        "refs": cve.get("refs", []),
                        "source": svc.get("source", "network"),
                        "_kev_entry": kev_entry,
                        "_lead_steps": [],
                    }
                    findings.append(f)
                    device_cves.append(cve["cve_id"])

        per_host.append({"host": host, "host_id": host_id,
                         "findings": findings, "cves": device_cves})

    # ---- Phase 2: batch EPSS for every CVE we saw ------------------------
    all_cves = sorted({f["cve_id"] for ph in per_host for f in ph["findings"]})
    epss_map = epss.scores_for(all_cves) if all_cves else {}
    print(f"[scan #{scan_id}] EPSS scored {len(epss_map)} CVE(s)", file=sys.stderr)

    # ---- Phase 3: enrich, score, persist ---------------------------------
    total_findings = 0
    seen_rows: list[dict] = []
    for ph in per_host:
        host, host_id = ph["host"], ph["host_id"]
        host_key = host["host_key"]
        for f in ph["findings"]:
            e = epss_map.get(f["cve_id"].upper(), {})
            f["epss"] = e.get("epss", 0.0)
            f["epss_pct"] = e.get("percentile", 0.0)
            f["priority"] = _priority(f)
            lead = f.pop("_lead_steps", [])
            f["remediation"] = lead + steps_for(f, f.pop("_kev_entry", None))
            key = (host_key, f["cve_id"], f.get("port") or 0)
            status = "PERSISTING" if key in prior_keys else "NEW"
            db.add_finding(scan_id, host_id, host_key, f, status)
            seen_rows.append({"host_key": host_key, "cve_id": f["cve_id"],
                              "port": f.get("port")})
            total_findings += 1

        advice = check_firmware(host, ph["cves"])
        if advice:
            db.add_service(host_id, {
                "port": 0, "proto": "info", "state": "info",
                "service": "firmware-advice", "product": advice.vendor,
                "version": advice.current_version, "cpe": advice.advisory_url,
            })
        db.set_host_risk(host_id, _risk_score(ph["findings"]))

    # ---- Patch verification: present last scan, absent now = resolved ----
    resolved_rows = []
    for key, row in prior_full.items():
        if key not in current_keys:
            resolved_rows.append({
                "host_key": row["host_key"], "ip": row.get("ip"),
                "cve_id": row["cve_id"], "port": row.get("port"),
                "severity": row.get("severity"), "is_kev": row.get("is_kev"),
            })
    db.record_resolved(scan_id, resolved_rows)

    ts = time.time()
    db.mark_lifecycle_seen(seen_rows, ts)
    db.mark_lifecycle_resolved(resolved_rows, ts)

    # hosts_attempted derives from the same target expansion the scanner used
    # (CIDR/range/plain-IP targets). Hostname or otherwise unparseable targets
    # expand to nothing, in which case attempted/failed aren't derivable --
    # store NULL rather than a misleading 0 (host_count/"succeeded" is
    # unaffected either way).
    target_ips = set(_expand_targets(cfg.targets))
    if target_ips:
        excluded_ips = set(_expand_targets(cfg.exclude))
        hosts_attempted = len(target_ips - excluded_ips)
        hosts_failed = max(0, hosts_attempted - len(hosts))
    else:
        hosts_attempted = None
        hosts_failed = None

    db.finish_scan(scan_id, host_count=len(hosts), finding_count=total_findings,
                   hosts_attempted=hosts_attempted, hosts_failed=hosts_failed)
    print(f"[scan #{scan_id}] done: {total_findings} finding(s), "
          f"{len(resolved_rows)} resolved since last scan", file=sys.stderr)
    db.close()
    return scan_id
