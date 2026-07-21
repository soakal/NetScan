"""Turn a correlated finding into concrete, ordered remediation steps.

Priority order for guidance:
  1. If it's in CISA KEV, lead with CISA's mandated action + due date — these
     are exploited in the wild and must be fixed first.
  2. Product-specific upgrade guidance for common software we recognize.
  3. A sensible generic fallback (patch to a fixed release, restrict exposure,
     verify on next scan).

Each step is a plain string so the report can render them as a checklist and
the operator can tick them off.
"""
from __future__ import annotations

from typing import Any

# Light product knowledge base for nicer, more specific steps. Keyed by a
# lowercase substring of the detected product/CPE.
_PRODUCT_GUIDANCE = {
    "openssh": [
        "Identify the running OpenSSH version on the host (ssh -V).",
        "Update OpenSSH via the OS package manager (apt/yum/dnf/zypper) and "
        "restart sshd.",
        "Restrict SSH exposure: limit source IPs at the firewall, disable "
        "password auth in favor of keys.",
    ],
    "apache": [
        "Confirm the installed httpd version (httpd -v / apache2 -v).",
        "Apply the vendor package update for Apache HTTP Server and restart "
        "the service.",
        "Disable unused modules and ensure the server is not exposing version "
        "banners (ServerTokens Prod).",
    ],
    "nginx": [
        "Check the running nginx version (nginx -v).",
        "Upgrade nginx to the latest stable/LTS release via your package repo "
        "and reload.",
    ],
    "openssl": [
        "Determine the OpenSSL version (openssl version).",
        "Patch OpenSSL through the OS package manager and restart every service "
        "linked against it (web servers, mail, VPN, etc.).",
    ],
    "microsoft": [
        "Map the CVE to its Microsoft security update (KB) via the MSRC update "
        "guide.",
        "Deploy the KB through WSUS / Intune / SCCM, or manually for ad-hoc "
        "hosts, then reboot if required.",
        "Confirm the patch is reported as installed (Get-HotFix / wmic qfe).",
    ],
    "windows": [
        "Identify the applicable Microsoft monthly rollup or out-of-band update "
        "for this CVE.",
        "Deploy via your patch-management tooling (WSUS/Intune/SCCM) and reboot.",
        "Verify with Get-HotFix or by re-running this scan.",
    ],
    "samba": [
        "Check the smbd version (smbd -V).",
        "Update Samba via the OS package manager and restart smbd/nmbd.",
    ],
    "vsftpd": [
        "Update vsftpd via the package manager; consider disabling FTP in favor "
        "of SFTP.",
    ],
    "php": [
        "Determine the PHP version (php -v) and the SAPI in use (fpm/cli/module).",
        "Upgrade to a supported PHP branch and restart php-fpm / the web server.",
    ],
}


def steps_for(finding: dict[str, Any], kev_entry: dict | None) -> list[str]:
    steps: list[str] = []

    if kev_entry:
        action = kev_entry.get("requiredAction")
        due = kev_entry.get("dueDate")
        steps.append(
            "PRIORITY — this CVE is in CISA's Known Exploited Vulnerabilities "
            "catalog (actively exploited). Treat as urgent."
        )
        if action:
            steps.append(f"CISA required action: {action}")
        if due:
            steps.append(f"CISA remediation due date (for federal agencies): {due}.")

    product = (finding.get("product") or "").lower()
    cpe = (finding.get("cpe") or "").lower()
    matched = None
    for key, guidance in _PRODUCT_GUIDANCE.items():
        if key in product or key in cpe:
            matched = guidance
            break
    if matched:
        steps.extend(matched)
    else:
        svc = finding.get("service") or "the affected service"
        steps.extend([
            f"Identify the exact version of {finding.get('product') or svc} "
            f"running on port {finding.get('port')}.",
            "Consult the CVE references for the fixed version, then apply the "
            "vendor patch or upgrade.",
            "If no patch is available yet, apply mitigations (restrict network "
            "exposure, disable the feature, or take the service offline).",
        ])

    steps.append(
        "Re-run a NetScan scan after patching — the finding should move to "
        "'Resolved' once the fixed version is detected."
    )
    return steps
