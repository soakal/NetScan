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

def _nmap_upgrade_hint() -> str:
    if sys.platform == "win32":
        # winget's own "Insecure.Nmap" package is stuck at 7.80 -- the exact
        # buggy version this warning is about -- so "winget upgrade" is a
        # dead end here. setup.bat installs straight from nmap.org instead.
        return "run setup.bat (installs the current nmap release from nmap.org -- winget's own package is stuck at 7.80 and can't fix this)"
    if sys.platform == "darwin":
        return "brew upgrade nmap"
    return "your distro's package manager (apt/dnf/pacman/etc.)"


def _warn_if_buggy_nmap(scanner: "nmap.PortScanner") -> None:
    """nmap 7.80 has a known crash bug (nmap/nmap#1764): a stray ARP reply
    arriving after --host-timeout stops a target's clock hits an internal
    assertion ("Assertion failed: htn.toclock_running == true, Target.cc")
    and aborts the whole scan. It's most likely on large target lists.
    Fixed upstream in 7.90. We can't fix nmap's own bug, just warn and
    (in _scan_with_nmap) retry with the known workaround if it happens."""
    version = scanner.nmap_version()
    if version and version != (0, 0) and version < (7, 90):
        print(f"[warn] nmap {version[0]}.{version[1]} detected -- versions before "
              "7.90 have a known crash bug on large scans (nmap/nmap#1764). "
              "If the scan aborts with 'Assertion failed: htn.toclock_running', "
              f"upgrade nmap: {_nmap_upgrade_hint()}",
              file=sys.stderr)


# nmap 7.80's crash bug (nmap/nmap#1764) shows up on target lists roughly
# above ~100 hosts and isn't reliably avoided by --max-parallelism alone (we
# saw it recur with that flag on a 766-host scan). Splitting the run into
# small per-invocation chunks keeps each nmap process well under the
# threshold, and confines a crash to the one chunk that triggered it instead
# of losing the whole scan's results.
_NMAP_CHUNK_SIZE = 48


def _parse_nmap_host(scanner: "nmap.PortScanner", ip: str) -> dict[str, Any] | None:
    h = scanner[ip]
    if h.state() != "up":
        return None

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

    return {
        "ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
        "os_name": os_name, "os_accuracy": os_acc, "device_type": device_type,
        "host_key": host_key, "services": services,
    }


def _scan_chunk(scanner: "nmap.PortScanner", chunk_targets: str, extra: str,
                 label: str) -> list[str]:
    """Run one nmap invocation over a chunk of targets. On the known nmap
    7.80 assertion crash, retry once with --max-parallelism 10; if it crashes
    again, skip the chunk (log + return no hosts) rather than aborting the
    whole scan. Any other PortScannerError propagates."""
    try:
        scanner.scan(hosts=chunk_targets, arguments=extra)
        return scanner.all_hosts()
    except nmap.PortScannerError as exc:
        if "Assertion failed" not in str(exc):
            raise
        if "--max-parallelism" not in extra:
            print(f"[warn] nmap crashed on {label} ({exc}); retrying with "
                  "--max-parallelism 10 (known workaround for nmap/nmap#1764)",
                  file=sys.stderr)
            try:
                scanner.scan(hosts=chunk_targets, arguments=extra + " --max-parallelism 10")
                return scanner.all_hosts()
            except nmap.PortScannerError as exc2:
                exc = exc2
        print(f"[warn] {label} crashed nmap twice ({exc}); skipping this "
              "chunk. This is a known nmap 7.80 bug (nmap/nmap#1764) fixed "
              f"in nmap 7.90+ -- upgrade to resolve it permanently: "
              f"{_nmap_upgrade_hint()}", file=sys.stderr)
        return []


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

    extra = args
    ips = _expand_targets(cfg.targets)
    if cfg.exclude:
        # strict=True: an exclude entry we can't parse must not silently
        # fail to exclude that host -- it exists to protect fragile devices,
        # so failing open (scanning it anyway) is the wrong default.
        excluded = set(_expand_targets(cfg.exclude, strict=True))
        ips = [ip for ip in ips if ip not in excluded]
    # Overlapping target specs (e.g. a CIDR plus one of its own IPs) can
    # repeat an address; dedupe so it isn't scanned -- and inserted into the
    # DB -- twice under an identical host_key.
    ips = list(dict.fromkeys(ips))

    chunks = [ips[i:i + _NMAP_CHUNK_SIZE] for i in range(0, len(ips), _NMAP_CHUNK_SIZE)]
    print(f"[nmap] scanning {len(ips)} addresses in {len(chunks)} chunk(s) of "
          f"up to {_NMAP_CHUNK_SIZE}\n[nmap] args: {extra}", file=sys.stderr)
    _warn_if_buggy_nmap(scanner)

    hosts: list[dict[str, Any]] = []
    for i, chunk in enumerate(chunks, start=1):
        label = f"chunk {i}/{len(chunks)} ({chunk[0]}-{chunk[-1]})"
        for ip in _scan_chunk(scanner, " ".join(chunk), extra, label):
            parsed = _parse_nmap_host(scanner, ip)
            if parsed:
                hosts.append(parsed)

    # Two different IPs can legitimately report the same MAC (cloned VM
    # templates, some virtual-switch/NAT setups) or illegitimately (ARP
    # spoofing) -- either way host_key (UNIQUE per scan) would collide and
    # crash the DB insert. Disambiguate every host sharing a MAC by folding
    # the IP into its key, and flag it so it surfaces as a signal rather
    # than silently changing identity.
    mac_counts: dict[str, int] = {}
    for h in hosts:
        if h["mac"]:
            mac_counts[h["mac"]] = mac_counts.get(h["mac"], 0) + 1
    for h in hosts:
        if h["mac"] and mac_counts[h["mac"]] > 1:
            h["host_key"] = f"{h['mac']}|{h['ip']}"
            h["duplicate_mac"] = True
            print(f"[warn] {h['ip']} shares MAC {h['mac']} with "
                  f"{mac_counts[h['mac']] - 1} other host(s) -- possible "
                  f"cloned VM or ARP spoofing", file=sys.stderr)

    return hosts


# ---------------------------------------------------------------------------
# Pure-Python fallback path
# ---------------------------------------------------------------------------

def _expand_targets(targets: list[str], strict: bool = False) -> list[str]:
    """Expand CIDR/`a.b.c.d-e`/plain-IP target specs into individual IPs.
    Hostnames and anything else nmap's own target grammar understands are
    NOT supported here -- by default such entries are skipped with a warning
    (matches nmap's own resolve-it-for-me behavior closely enough for stats
    purposes). Pass strict=True to raise instead: used for `exclude`, where
    silently failing to honor an entry means scanning a host the caller
    explicitly asked to skip -- fail closed, not open."""
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
            if strict:
                raise ValueError(
                    f"exclude entry {t!r} isn't a plain IP, CIDR, or "
                    "a.b.c.d-e range -- refusing to scan rather than silently "
                    "failing to exclude it"
                ) from None
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
        # Not "winget install Insecure.Nmap" -- that package is stuck at
        # 7.80, which has a known crash bug on large scans (nmap/nmap#1764).
        install_hint = "run setup.bat (then open a new terminal)"
    elif sys.platform == "darwin":
        install_hint = "brew install nmap"
    else:
        install_hint = "sudo apt install nmap  (or dnf/pacman/etc. for your distro)"
    print("[warn] nmap not found — using the pure-Python fallback scanner. "
          "Install nmap for OS detection and CPE-based CVE correlation: "
          f"{install_hint}", file=sys.stderr)
    return _scan_with_sockets(cfg)
