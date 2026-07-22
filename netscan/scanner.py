"""Host discovery and service fingerprinting.

Primary engine is nmap (via the python-nmap wrapper) because its service/version
detection emits CPE strings, which are exactly what we need to look CVEs up by.
If nmap isn't installed we fall back to a basic pure-Python TCP connect +
banner-grab scanner. The fallback finds open ports and grabs banners but can't
produce reliable CPEs, so CVE correlation will be limited in that mode.

Nothing in here exploits anything. We connect, read banners, and let nmap do
version/OS *detection*. No NSE "vuln"/exploit scripts are ever invoked. This is
deliberate: detection traffic is far less likely to trip IDS/IPS or endpoint
protection than active exploitation, which keeps scans low-impact.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .config import Config, FALLBACK_PORTS

try:
    import nmap  # python-nmap
    _HAVE_NMAP = True
except ImportError:
    _HAVE_NMAP = False


def nmap_available() -> bool:
    """True if both the python-nmap wrapper and the nmap binary are present."""
    if not _HAVE_NMAP:
        return False
    try:
        nmap.PortScanner()
        return True
    except Exception:
        return False


def _os_detection_allowed() -> bool:
    """nmap's -O hard-requires actual root (euid 0) -- Linux capabilities
    like cap_net_raw/cap_net_admin (which are enough for -sS/-sV) do NOT
    satisfy it. On Windows there's no geteuid() and no confirmed equivalent
    hard-block, so we let it proceed and rely on nmap's own error surfacing."""
    if not hasattr(os, "geteuid"):
        return True
    return os.geteuid() == 0


def cpe22_to_23(cpe: str) -> str:
    """Convert an nmap-style CPE 2.2 URI (cpe:/a:vendor:product:version) to the
    CPE 2.3 formatted string NVD expects (cpe:2.3:a:vendor:product:version:*:...).
    """
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        return cpe
    body = cpe[len("cpe:/"):]
    parts = body.split(":")
    # parts: part, vendor, product, version, update, edition, lang
    fields = (parts + ["*"] * 7)[:7]
    part, vendor, product, version, update, edition, lang = fields
    # CPE 2.3 has 11 components after the prefix.
    comps = [part or "*", vendor or "*", product or "*", version or "*",
             update or "*", edition or "*", lang or "*", "*", "*", "*", "*"]
    comps = [c if c else "*" for c in comps]
    return "cpe:2.3:" + ":".join(comps)


# ---------------------------------------------------------------------------
# nmap path
# ---------------------------------------------------------------------------

def _scan_with_nmap(cfg: Config) -> list[dict[str, Any]]:
    scanner = nmap.PortScanner()
    profile = cfg.profile
    args = profile["nmap_args"]
    if profile.get("os_detection"):
        if _os_detection_allowed():
            args += " -O"
        else:
            print("[warn] OS detection (-O) requires root -- skipping it for "
                  "this scan. Re-run with sudo for OS fingerprinting. (nmap "
                  "requires euid 0 for -O; setcap capabilities are not "
                  "sufficient.)", file=sys.stderr)

    targets = " ".join(cfg.targets)
    extra = args
    if cfg.exclude:
        extra += " --exclude " + ",".join(cfg.exclude)

    print(f"[nmap] scanning {targets}\n[nmap] args: {extra}", file=sys.stderr)
    scanner.scan(hosts=targets, arguments=extra)

    hosts: list[dict[str, Any]] = []
    for ip in scanner.all_hosts():
        h = scanner[ip]
        if h.state() != "up":
            continue

        mac = h["addresses"].get("mac")
        vendor = None
        if mac and h.get("vendor"):
            vendor = h["vendor"].get(mac)

        os_name, os_acc, device_type = None, None, None
        osmatches = h.get("osmatch") or []
        if osmatches:
            os_name = osmatches[0].get("name")
            os_acc = int(osmatches[0].get("accuracy") or 0)
            classes = osmatches[0].get("osclass") or []
            if classes:
                device_type = classes[0].get("type")

        hostname = None
        names = h.get("hostnames") or []
        if names and names[0].get("name"):
            hostname = names[0]["name"]

        host_key = mac or ip
        services: list[dict[str, Any]] = []
        for proto in ("tcp", "udp"):
            for port in sorted(h.all_protocols() and h[proto].keys() if proto in h else []):
                p = h[proto][port]
                if p.get("state") not in ("open", "open|filtered"):
                    continue
                cpe_field = p.get("cpe") or ""
                cpes = [cpe22_to_23(c) for c in re.split(r"[\s,]+", cpe_field) if c]
                services.append({
                    "port": int(port),
                    "proto": proto,
                    "state": p.get("state"),
                    "service": p.get("name"),
                    "product": p.get("product") or None,
                    "version": p.get("version") or None,
                    "extrainfo": p.get("extrainfo") or None,
                    "cpe": cpes[0] if cpes else None,
                    "cpes": cpes,
                })

        hosts.append({
            "ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
            "os_name": os_name, "os_accuracy": os_acc, "device_type": device_type,
            "host_key": host_key, "services": services,
        })
    return hosts


# ---------------------------------------------------------------------------
# Pure-Python fallback path
# ---------------------------------------------------------------------------

def _expand_targets(targets: list[str]) -> list[str]:
    ips: list[str] = []
    for t in targets:
        t = t.strip()
        try:
            if "/" in t:
                net = ipaddress.ip_network(t, strict=False)
                ips.extend(str(h) for h in net.hosts())
            elif "-" in t and t.count(".") == 3:
                # 192.168.1.10-50 style
                base, rng = t.rsplit(".", 1)
                lo, hi = rng.split("-")
                ips.extend(f"{base}.{i}" for i in range(int(lo), int(hi) + 1))
            else:
                ips.append(str(ipaddress.ip_address(t)))
        except ValueError:
            print(f"[warn] skipping unparseable target {t!r}", file=sys.stderr)
    return ips


def _grab_banner(ip: str, port: int, timeout: float = 1.5) -> tuple[bool, str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                # nudge HTTP-ish services to talk
                if port in (80, 8000, 8080, 8008):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = s.recv(256)
                return True, data.decode("latin-1", "replace").strip()
            except (socket.timeout, OSError):
                return True, ""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, ""


def _scan_host_fallback(ip: str) -> dict[str, Any] | None:
    services = []
    for port in FALLBACK_PORTS:
        ok, banner = _grab_banner(ip, port)
        if ok:
            services.append({
                "port": port, "proto": "tcp", "state": "open",
                "service": _guess_service(port), "product": None,
                "version": _version_from_banner(banner), "cpe": None, "cpes": [],
                "banner": banner,
            })
    if not services:
        # Liveness check on common ports failed; treat as down for the fallback.
        return None
    hostname = None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except OSError:
        pass
    return {
        "ip": ip, "mac": None, "vendor": None, "hostname": hostname,
        "os_name": None, "os_accuracy": None, "device_type": None,
        "host_key": ip, "services": services,
    }


_COMMON = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 8080: "http-proxy",
    9100: "jetdirect",
}


def _guess_service(port: int) -> str:
    return _COMMON.get(port, "unknown")


def _version_from_banner(banner: str) -> str | None:
    if not banner:
        return None
    m = re.search(r"(\d+\.\d+[\w.\-]*)", banner)
    return m.group(1) if m else None


def _scan_with_sockets(cfg: Config) -> list[dict[str, Any]]:
    ips = _expand_targets(cfg.targets)
    excluded = set(_expand_targets(cfg.exclude))
    ips = [ip for ip in ips if ip not in excluded]
    print(f"[fallback] scanning {len(ips)} addresses (no nmap; limited fingerprinting)",
          file=sys.stderr)
    hosts: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(_scan_host_fallback, ip): ip for ip in ips}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                hosts.append(res)
    return hosts


# ---------------------------------------------------------------------------
# public entrypoint
# ---------------------------------------------------------------------------

def discover_and_fingerprint(cfg: Config) -> list[dict[str, Any]]:
    """Return a list of host dicts, each with a `services` list."""
    if nmap_available():
        return _scan_with_nmap(cfg)
    if sys.platform == "win32":
        install_hint = "winget install --id Insecure.Nmap -e (then open a new terminal)"
    elif sys.platform == "darwin":
        install_hint = "brew install nmap"
    else:
        install_hint = "sudo apt install nmap  (or dnf/pacman/etc. for your distro)"
    print("[warn] nmap not found — using the pure-Python fallback scanner. "
          "Install nmap for OS detection and CPE-based CVE correlation: "
          f"{install_hint}", file=sys.stderr)
    return _scan_with_sockets(cfg)
