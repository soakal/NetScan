"""Firmware advisory checks for network infrastructure (switches, routers, APs,
firewalls, printers...).

Vendors publish firmware fixes through wildly different channels — some have
clean machine-readable PSIRT/CSAF feeds (Cisco, Palo Alto), many only have HTML
advisory pages, and plenty require an authenticated support contract to even see
release notes. So this is built as a *registry of vendor handlers*. Each handler
takes a fingerprinted device and returns advisory info. Where we can't reliably
automate a vendor, we still produce an actionable pointer: the current detected
version, the vendor's security-advisory URL, and any CVEs we already correlated
for that device's CPE so you know whether a firmware bump is urgent.

Add a vendor by writing a function `(device) -> FirmwareAdvice | None` and
registering it in VENDOR_HANDLERS keyed by a lowercase vendor substring.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class FirmwareAdvice:
    vendor: str
    model: str | None = None
    current_version: str | None = None
    latest_version: str | None = None
    update_available: bool | None = None        # None = couldn't determine
    advisory_url: str | None = None
    notes: str = ""
    fixed_cves: list[str] = field(default_factory=list)


# Known vendor security-advisory entry points. Pointers, not scrapers — keeping
# these as links avoids brittle HTML scraping and login walls, and they're the
# authoritative place to confirm a fix.
VENDOR_ADVISORY_URLS = {
    "cisco": "https://sec.cloud.tools.cisco.com/security/center/publicationListing.x",
    "juniper": "https://supportportal.juniper.net/JSA",
    "arista": "https://www.arista.com/en/support/advisories-notices",
    "hp": "https://support.hpe.com/connect/s/securitybulletinlibrary",
    "hewlett": "https://support.hpe.com/connect/s/securitybulletinlibrary",
    "aruba": "https://www.arubanetworks.com/support-services/security-bulletins/",
    "netgear": "https://www.netgear.com/about/security/",
    "ubiquiti": "https://community.ui.com/releases",
    "mikrotik": "https://mikrotik.com/download/changelogs",
    "fortinet": "https://www.fortiguard.com/psirt",
    "palo alto": "https://security.paloaltonetworks.com/",
    "dell": "https://www.dell.com/support/security/",
    "tp-link": "https://www.tp-link.com/us/support/download/",
    "zyxel": "https://www.zyxel.com/global/en/support/security-advisories",
    "brother": "https://www.brother.com/",
    "canon": "https://www.canon.com/support/",
}

NETWORK_DEVICE_TYPES = {
    "router", "switch", "firewall", "wap", "access point", "bridge",
    "broadband router", "load balancer", "printer", "print server", "webcam",
    "storage-misc", "specialized",
}


def looks_like_network_device(device: dict[str, Any]) -> bool:
    dt = (device.get("device_type") or "").lower()
    if any(t in dt for t in NETWORK_DEVICE_TYPES):
        return True
    # Vendor heuristic from MAC OUI / OS fingerprint.
    blob = " ".join(filter(None, [device.get("vendor"), device.get("os_name")])).lower()
    return any(v in blob for v in VENDOR_ADVISORY_URLS)


def _detect_vendor(device: dict[str, Any]) -> str | None:
    blob = " ".join(filter(None, [device.get("vendor"), device.get("os_name")])).lower()
    for v in VENDOR_ADVISORY_URLS:
        if v in blob:
            return v
    return None


def _generic_handler(device: dict[str, Any], cves: list[str]) -> FirmwareAdvice | None:
    vendor = _detect_vendor(device)
    if not vendor:
        return None
    version = None
    # Try to lift a version out of any service CPE / OS string.
    os_name = device.get("os_name") or ""
    return FirmwareAdvice(
        vendor=vendor,
        model=device.get("os_name"),
        current_version=version,
        latest_version=None,
        update_available=bool(cves) or None,
        advisory_url=VENDOR_ADVISORY_URLS.get(vendor),
        fixed_cves=cves,
        notes=(
            "Automated firmware-version comparison isn't available for this "
            "vendor. Confirm the running firmware on the device, then check the "
            "linked security-advisory page for a release that fixes the CVEs "
            "listed above. " + (
                "CVEs were correlated to this device, so a firmware update is "
                "likely required." if cves else
                "No CVEs correlated yet, but keeping firmware current is advised."
            )
        ),
    )


# Vendors with a more specific handler can override the generic one here.
# (Stubs left intentionally simple; wire up CSAF/PSIRT feeds as needed.)
VENDOR_HANDLERS: dict[str, Callable[[dict, list[str]], FirmwareAdvice | None]] = {}


def check_firmware(device: dict[str, Any], correlated_cves: list[str]) -> FirmwareAdvice | None:
    """Return firmware advice for a device, or None if it isn't recognized as
    network infrastructure / no vendor could be determined."""
    if not looks_like_network_device(device):
        return None
    vendor = _detect_vendor(device)
    if vendor and vendor in VENDOR_HANDLERS:
        advice = VENDOR_HANDLERS[vendor](device, correlated_cves)
        if advice:
            return advice
    return _generic_handler(device, correlated_cves)
