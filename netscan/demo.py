"""Seed the database with realistic-looking synthetic findings so the report
can be explored without touching a real network or the internet. Used by
`python run.py demo` and by the test suite.
"""
from __future__ import annotations

import time

from .db import Database
from .remediation import steps_for
from .taxonomy import cwe_name, owasp_family_for

_HOSTS = [
    {"ip": "192.168.1.10", "mac": "00:0c:29:aa:bb:01", "hostname": "fileserver01",
     "vendor": "VMware", "os_name": "Microsoft Windows Server 2019 Standard",
     "os_accuracy": 95, "os_build": "17763", "device_type": "general purpose",
     "auth_method": "winrm"},
    {"ip": "192.168.1.20", "mac": "b8:27:eb:11:22:33", "hostname": "web01",
     "vendor": "Raspberry Pi Foundation", "os_name": "Ubuntu 22.04.3 LTS",
     "os_accuracy": 92, "os_build": "22.04", "device_type": "general purpose",
     "auth_method": "ssh"},
    {"ip": "192.168.1.1", "mac": "00:1b:0d:aa:00:01", "hostname": "core-sw1",
     "vendor": "Cisco Systems", "os_name": "Cisco IOS 15.2", "os_accuracy": 90,
     "device_type": "switch", "auth_method": "network"},
]

# (host_idx, port, service, product, version, cpe, cve, cvss, sev, cwe, kev, ransom, epss, epss_pct)
_F = [
    (0, 445, "microsoft-ds", "Microsoft Windows", "Server 2019",
     "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*",
     "CVE-2020-0796", 10.0, "Critical", "CWE-787", True, True, 0.94, 0.99),
    (0, 3389, "ms-wbt-server", "Microsoft Terminal Services", "",
     "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*",
     "CVE-2019-0708", 9.8, "Critical", "CWE-416", True, True, 0.97, 0.99),
    (1, 22, "ssh", "OpenSSH", "7.4",
     "cpe:2.3:a:openssh:openssh:7.4:*:*:*:*:*:*:*",
     "CVE-2018-15473", 5.3, "Medium", "CWE-200", False, False, 0.62, 0.95),
    (1, 80, "http", "Apache httpd", "2.4.49",
     "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
     "CVE-2021-41773", 7.5, "High", "CWE-22", True, False, 0.975, 0.99),
    (1, 443, "https", "OpenSSL", "1.0.1",
     "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",
     "CVE-2014-0160", 7.5, "High", "CWE-125", False, False, 0.91, 0.98),
    (2, 23, "telnet", "Cisco IOS", "15.2",
     "cpe:2.3:o:cisco:ios:15.2:*:*:*:*:*:*:*",
     "CVE-2017-3881", 9.8, "Critical", "CWE-787", True, False, 0.55, 0.94),
]


def seed(db_path: str) -> int:
    db = Database(db_path)
    scan_id = db.create_scan("demo", ["192.168.1.0/24"])
    host_ids = []
    for h in _HOSTS:
        h2 = dict(h, host_key=h["mac"], vt_malicious=0)
        host_ids.append(db.add_host(scan_id, h2))

    # services
    for (hi, port, svc, prod, ver, cpe, *_rest) in _F:
        db.add_service(host_ids[hi], {"port": port, "proto": "tcp", "state": "open",
                                      "service": svc, "product": prod,
                                      "version": ver, "cpe": cpe})
    # cisco firmware advice card
    db.add_service(host_ids[2], {"port": 0, "proto": "info", "state": "info",
                                 "service": "firmware-advice", "product": "cisco",
                                 "version": "15.2",
                                 "cpe": "https://sec.cloud.tools.cisco.com/security/center/publicationListing.x"})

    # --- credentialed-scan artifacts (demo) ---
    # Windows host (winrm): installed hotfixes + a few installed apps.
    for kb in ["KB5031361", "KB5031564", "KB890830", "KB5030214", "KB4023057"]:
        db.add_fact(host_ids[0], "hotfix", kb)
    db.add_fact(host_ids[0], "package_count", "4")
    for name, ver in [("Microsoft Edge", "120.0.2210.91"),
                      ("7-Zip 22.01 (x64)", "22.01"),
                      ("Mozilla Firefox", "115.0"),
                      ("Notepad++ (64-bit)", "8.5.4")]:
        db.add_service(host_ids[0], {"port": 0, "proto": "pkg", "state": "installed",
                                     "service": name, "product": name, "version": ver,
                                     "cpe": None, "source": "winrm"})
    # Linux host (ssh): package inventory, a couple CPE-matched.
    db.add_fact(host_ids[1], "kernel", "5.15.0-89-generic")
    db.add_fact(host_ids[1], "package_count", "5")
    for name, ver, cpe in [
        ("openssh-server", "8.9p1", "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"),
        ("openssl", "3.0.2", "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"),
        ("nginx", "1.18.0", None), ("bash", "5.1.16", None), ("curl", "7.81.0", None)]:
        db.add_service(host_ids[1], {"port": 0, "proto": "pkg", "state": "installed",
                                     "service": name, "product": name, "version": ver,
                                     "cpe": cpe, "source": "ssh"})

    count = 0
    per_host_findings = {0: [], 1: [], 2: []}
    for (hi, port, svc, prod, ver, cpe, cve, cvss, sev, cwe, kev, ransom, epss, pct) in _F:
        okey, oname = owasp_family_for(cwe)
        kev_entry = {"requiredAction": "Apply vendor updates per vendor instructions.",
                     "dueDate": "2024-12-31",
                     "knownRansomwareCampaignUse": "Known" if ransom else "Unknown"} if kev else None
        f = {
            "cve_id": cve, "port": port, "service": svc, "product": prod,
            "version": ver, "cpe": cpe, "cvss": cvss, "severity": sev,
            "is_kev": kev, "ransomware": ransom, "cwe": cwe,
            "cwe_name": cwe_name(cwe), "owasp_key": okey, "owasp_name": oname,
            "epss": epss, "epss_pct": pct,
            "summary": f"Synthetic demo finding for {prod} {ver}.",
            "refs": [f"https://nvd.nist.gov/vuln/detail/{cve}"],
        }
        f["priority"] = round(cvss * 10 + epss * 60 + (40 if kev else 0) + (20 if ransom else 0), 1)
        f["remediation"] = steps_for(f, kev_entry)
        db.add_finding(scan_id, host_ids[hi], _HOSTS[hi]["mac"], f, "NEW")
        per_host_findings[hi].append(f)
        count += 1

    # risk scores
    for hi, hid in enumerate(host_ids):
        fs = per_host_findings[hi]
        score = sum((40 if x["severity"] == "Critical" else 20 if x["severity"] == "High"
                     else 8 if x["severity"] == "Medium" else 2)
                    * (2.5 if x["is_kev"] else 1) * (1 + x["epss"]) for x in fs)
        db.set_host_risk(hid, round(score, 1))

    # --- credentialed-backend findings (demo) ---
    # OVAL (Linux/web01): backport-aware package finding, source='oval'.
    oval_f = {
        "cve_id": "CVE-2023-38408", "port": 0, "service": "openssh-server",
        "product": "openssh-server", "version": "1:8.9p1-3ubuntu0.4",
        "cpe": None, "cvss": 9.8, "severity": "Critical", "is_kev": False,
        "ransomware": False, "cwe": "CWE-426", "cwe_name": cwe_name("CWE-426"),
        "owasp_key": owasp_family_for("CWE-426")[0],
        "owasp_name": owasp_family_for("CWE-426")[1],
        "epss": 0.43, "epss_pct": 0.93, "source": "oval",
        "summary": "Remote code execution in OpenSSH's forwarded ssh-agent (demo).",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
    }
    oval_f["priority"] = round(9.8 * 10 + 0.43 * 60, 1)
    oval_f["remediation"] = ["Upgrade openssh-server to 1:8.9p1-3ubuntu0.6 or later "
                             "(installed 1:8.9p1-3ubuntu0.4). `apt update && apt "
                             "upgrade openssh-server` and restart sshd."] + \
        steps_for(oval_f, None)
    db.add_finding(scan_id, host_ids[1], _HOSTS[1]["mac"], oval_f, "NEW")

    # MSRC (Windows/fileserver01): missing-patch finding, source='msrc'.
    msrc_f = {
        "cve_id": "CVE-2024-21338", "port": 0, "service": "KB5034127",
        "product": "Microsoft", "version": None, "cpe": None,
        "cvss": 7.8, "severity": "High", "is_kev": True, "ransomware": False,
        "cwe": "CWE-822", "cwe_name": cwe_name("CWE-822"),
        "owasp_key": owasp_family_for("CWE-822")[0],
        "owasp_name": owasp_family_for("CWE-822")[1],
        "epss": 0.12, "epss_pct": 0.85, "source": "msrc",
        "summary": "Windows Kernel elevation of privilege (demo).",
        "refs": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21338"],
    }
    msrc_f["priority"] = round(7.8 * 10 + 0.12 * 60 + 40, 1)
    msrc_f["remediation"] = ["Install Microsoft update KB5034127 (or a newer "
                             "cumulative update that supersedes it).",
                             "Deploy via WSUS / Intune / SCCM and reboot."] + \
        steps_for(msrc_f, {"requiredAction": "Apply updates.", "dueDate": "2024-03-05",
                           "knownRansomwareCampaignUse": "Unknown"})
    db.add_finding(scan_id, host_ids[0], _HOSTS[0]["mac"], msrc_f, "NEW")
    db.add_fact(host_ids[0], "msrc_patched", "61")
    db.add_fact(host_ids[0], "msrc_missing", "1")

    db.finish_scan(scan_id, host_count=len(_HOSTS), finding_count=count + 2)
    db.close()
    return count + 2
