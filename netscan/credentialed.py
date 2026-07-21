"""Credentialed (authenticated) scanning.

The operator provisions a least-privilege account on hosts they own; NetScan logs
in over the host's normal management protocol (SSH for *nix/network gear, WinRM
for Windows) and runs **read-only** inventory queries. Nothing is changed on the
target. This is the quietest scan mode (a normal management login, not external
probing) and by far the most accurate, because we read the actual OS build,
installed packages/versions, and — on Windows — installed hotfix (KB) IDs,
instead of guessing from network banners.

Design: the network I/O is thin; all output parsing lives in pure functions
(parse_os_release, parse_dpkg, parse_rpm, parse_win_os, parse_get_hotfix,
parse_win_software) that take raw command output and return structured data, so
they can be unit-tested without a live host.

Optional dependencies (import-guarded): `paramiko` (SSH), `pywinrm` (WinRM).
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field

from .config import Credential

try:
    import paramiko
    _HAVE_PARAMIKO = True
except ImportError:
    _HAVE_PARAMIKO = False

try:
    import winrm
    _HAVE_WINRM = True
except ImportError:
    _HAVE_WINRM = False


# One-time (per process) warning when scanning with unverified host identity.
# Default mode accepts unknown SSH host keys / self-signed WinRM certs so that a
# first scan of a fleet works without a pre-populated known_hosts — a documented
# tradeoff for an internal scanner. `strict_host_keys: true` opts into strict
# verification (SSH: reject unknown keys; WinRM: validate the TLS certificate).
_warned_unverified = False


def _warn_unverified_once() -> None:
    global _warned_unverified
    if not _warned_unverified:
        _warned_unverified = True
        print(
            "[credentialed] WARNING: host identity is NOT verified in this mode "
            "(SSH host keys auto-accepted, WinRM TLS certs not validated). A "
            "MITM on the scan path could capture the scan credential. Set "
            "`strict_host_keys: true` in config.yaml (with a populated "
            "~/.ssh/known_hosts and trusted WinRM certs) to enforce verification.",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# result container
# ---------------------------------------------------------------------------

@dataclass
class CredResult:
    auth_method: str                       # "ssh" | "winrm"
    os_name: str | None = None
    os_build: str | None = None
    os_cpe: str | None = None
    distro_id: str | None = None           # /etc/os-release ID (ssh)
    version_id: str | None = None          # /etc/os-release VERSION_ID (ssh)
    # package list: dicts with name, version, and (when confidently mapped) cpe
    packages: list[dict] = field(default_factory=list)
    hotfixes: list[str] = field(default_factory=list)
    kernel: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


# ---------------------------------------------------------------------------
# credential selection
# ---------------------------------------------------------------------------

def credential_for(host: dict, creds: list[Credential]) -> Credential | None:
    """Pick the first credential whose `match` covers the host's IP. An empty
    match list matches any host of that credential's type. SSH is preferred for
    hosts that look *nix, WinRM for Windows, but the network fingerprint is only
    a hint — we try whatever matches."""
    ip = host.get("ip")
    os_blob = (host.get("os_name") or "").lower()
    prefer = "winrm" if "windows" in os_blob else ("ssh" if os_blob else None)

    def matches(c: Credential) -> bool:
        if not c.match:
            return True
        for pat in c.match:
            try:
                if "/" in pat and ip and ipaddress.ip_address(ip) in ipaddress.ip_network(pat, strict=False):
                    return True
            except ValueError:
                pass
            if ip and fnmatch.fnmatch(ip, pat):
                return True
        return False

    candidates = [c for c in creds if matches(c)]
    if not candidates:
        return None
    if prefer:
        for c in candidates:
            if c.type == prefer:
                return c
    return candidates[0]


# ---------------------------------------------------------------------------
# CPE builders  (curated, high-confidence only — avoids false positives)
# ---------------------------------------------------------------------------

def _cpe(part: str, vendor: str, product: str, version: str) -> str:
    def esc(s: str) -> str:
        return re.sub(r"\s+", "_", s.strip().lower())
    tail = ":".join([esc(version) if version else "*"] + ["*"] * 6)
    return f"cpe:2.3:{part}:{esc(vendor)}:{esc(product)}:{tail}"


def os_cpe_linux(distro_id: str, version_id: str) -> str | None:
    d = (distro_id or "").lower()
    v = version_id or "*"
    table = {
        "ubuntu": ("o", "canonical", "ubuntu_linux"),
        "debian": ("o", "debian", "debian_linux"),
        "rhel": ("o", "redhat", "enterprise_linux"),
        "redhat": ("o", "redhat", "enterprise_linux"),
        "centos": ("o", "centos", "centos"),
        "rocky": ("o", "rocky", "rocky_linux"),
        "almalinux": ("o", "almalinux", "almalinux"),
        "fedora": ("o", "fedoraproject", "fedora"),
        "opensuse": ("o", "opensuse", "leap"),
        "sles": ("o", "suse", "linux_enterprise_server"),
    }
    if d in table:
        part, vendor, product = table[d]
        return _cpe(part, vendor, product, v)
    return None


def os_cpe_windows(caption: str, version: str) -> str | None:
    c = (caption or "").lower()
    mapping = [
        ("server 2022", ("o", "microsoft", "windows_server_2022")),
        ("server 2019", ("o", "microsoft", "windows_server_2019")),
        ("server 2016", ("o", "microsoft", "windows_server_2016")),
        ("windows 11", ("o", "microsoft", "windows_11")),
        ("windows 10", ("o", "microsoft", "windows_10")),
        ("windows server", ("o", "microsoft", "windows_server")),
    ]
    for needle, (part, vendor, product) in mapping:
        if needle in c:
            return f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*"
    return None


# package-name -> (vendor, product) for software with a stable, well-known CPE.
# Intentionally small/curated: we only auto-CPE things we're confident about,
# so credentialed scanning doesn't generate version-mismatch false positives.
_PKG_CPE = {
    "openssh": ("openbsd", "openssh"),
    "openssh-server": ("openbsd", "openssh"),
    "openssh-client": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "libssl": ("openssl", "openssl"),
    "apache2": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "bash": ("gnu", "bash"),
    "samba": ("samba", "samba"),
    "sudo": ("sudo_project", "sudo"),
    "curl": ("haxx", "curl"),
    "python3": ("python", "python"),
}


def package_cpe(name: str, version: str) -> str | None:
    key = name.lower()
    if key in _PKG_CPE:
        vendor, product = _PKG_CPE[key]
        v = version or ""
        # Drop a Debian epoch prefix like "1:8.9p1" -> "8.9p1".
        v = re.sub(r"^\d+:", "", v)
        # Drop distro revision/build suffix: "8.9p1-3ubuntu0.4" -> "8.9p1".
        v = re.split(r"[-+~]", v)[0]
        m = re.match(r"[0-9][0-9a-zA-Z.]*", v)
        return _cpe("a", vendor, product, m.group(0) if m else "")
    return None


# ---------------------------------------------------------------------------
# pure parsers (unit-testable)
# ---------------------------------------------------------------------------

def parse_os_release(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"')
    return out


def parse_dpkg(text: str) -> list[dict]:
    pkgs = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pkgs.append({"name": parts[0], "version": parts[1]})
    return pkgs


def parse_rpm(text: str) -> list[dict]:
    pkgs = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pkgs.append({"name": parts[0], "version": parts[1]})
    return pkgs


def _loads_relaxed(text: str):
    """PowerShell ConvertTo-Json emits a bare object for single results and an
    array for multiple. Normalize to a list."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def parse_win_os(json_text: str) -> dict:
    rows = _loads_relaxed(json_text)
    if not rows:
        return {}
    r = rows[0]
    return {"caption": r.get("Caption"), "version": r.get("Version"),
            "build": str(r.get("BuildNumber") or "")}


def parse_get_hotfix(json_text: str) -> list[str]:
    rows = _loads_relaxed(json_text)
    ids = []
    for r in rows:
        hid = r.get("HotFixID") if isinstance(r, dict) else None
        if hid:
            ids.append(hid)
    return ids


def parse_win_software(json_text: str) -> list[dict]:
    rows = _loads_relaxed(json_text)
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        name = r.get("DisplayName")
        ver = r.get("DisplayVersion")
        if name:
            out.append({"name": name, "version": ver or ""})
    return out


def _enrich_packages(pkgs: list[dict]) -> list[dict]:
    for p in pkgs:
        p["cpe"] = package_cpe(p["name"], p.get("version", ""))
    return pkgs


# ---------------------------------------------------------------------------
# SSH scanner
# ---------------------------------------------------------------------------

_SSH_OS_CMD = "cat /etc/os-release 2>/dev/null"
_SSH_KERNEL_CMD = "uname -r"
_SSH_DPKG_CMD = "dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null"
_SSH_RPM_CMD = "rpm -qa --qf '%{NAME} %{VERSION}\\n' 2>/dev/null"


def scan_ssh(host: dict, cred: Credential, timeout: float = 12.0,
             strict_host_keys: bool = False) -> CredResult:
    res = CredResult(auth_method="ssh")
    if not _HAVE_PARAMIKO:
        res.error = "paramiko not installed (pip install paramiko)"
        return res
    ip = host["ip"]
    client = paramiko.SSHClient()
    if strict_host_keys:
        # Strict: only hosts whose key is already in the system/user known_hosts
        # are accepted; anything unknown (or changed) fails the scan of that host.
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        # Default: accept unknown keys so a first scan of a new fleet works.
        # See _warn_unverified_once for the tradeoff.
        _warn_unverified_once()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip, port=cred.default_port(), username=cred.username,
            password=cred.password, key_filename=cred.key_file,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=bool(cred.key_file), allow_agent=False,
        )
    except Exception as e:  # paramiko raises many subtypes
        res.error = f"ssh connect failed: {e}"
        return res

    def run(cmd: str) -> str:
        try:
            _in, out, _err = client.exec_command(cmd, timeout=timeout)
            return out.read().decode("utf-8", "replace")
        except Exception:
            return ""

    try:
        osr = parse_os_release(run(_SSH_OS_CMD))
        res.os_name = osr.get("PRETTY_NAME") or osr.get("NAME")
        res.os_build = osr.get("VERSION_ID")
        res.distro_id = osr.get("ID")
        res.version_id = osr.get("VERSION_ID")
        res.os_cpe = os_cpe_linux(osr.get("ID", ""), osr.get("VERSION_ID", ""))
        res.kernel = run(_SSH_KERNEL_CMD).strip() or None

        distro = (osr.get("ID_LIKE", "") + " " + osr.get("ID", "")).lower()
        if "debian" in distro or "ubuntu" in distro:
            pkgs = parse_dpkg(run(_SSH_DPKG_CMD))
        else:
            pkgs = parse_rpm(run(_SSH_RPM_CMD))
        res.packages = _enrich_packages(pkgs)
    finally:
        client.close()
    return res


# ---------------------------------------------------------------------------
# WinRM scanner
# ---------------------------------------------------------------------------

_PS_OS = (
    "Get-CimInstance Win32_OperatingSystem | "
    "Select-Object Caption,Version,BuildNumber | ConvertTo-Json -Compress"
)
_PS_HOTFIX = "Get-HotFix | Select-Object HotFixID | ConvertTo-Json -Compress"
# Read installed software from both 64- and 32-bit uninstall hives. Read-only.
_PS_SOFTWARE = (
    "$p='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*';"
    "Get-ItemProperty $p -ErrorAction SilentlyContinue | "
    "Where-Object {$_.DisplayName} | "
    "Select-Object DisplayName,DisplayVersion | ConvertTo-Json -Compress"
)


def scan_winrm(host: dict, cred: Credential, timeout: float = 25.0,
               strict_host_keys: bool = False) -> CredResult:
    res = CredResult(auth_method="winrm")
    if not _HAVE_WINRM:
        res.error = "pywinrm not installed (pip install pywinrm)"
        return res
    ip = host["ip"]
    endpoint = f"{cred.scheme}://{ip}:{cred.default_port()}/wsman"
    if not strict_host_keys:
        _warn_unverified_once()
    try:
        session = winrm.Session(
            endpoint,
            auth=(cred.username, cred.password),
            transport="ntlm",
            # Default "ignore": internal hosts are often self-signed and a first
            # scan must work without cert provisioning. strict_host_keys opts
            # into full certificate validation.
            server_cert_validation="validate" if strict_host_keys else "ignore",
        )
    except Exception as e:
        res.error = f"winrm session error: {e}"
        return res

    def run_ps(script: str) -> str:
        try:
            r = session.run_ps(script)
            if r.status_code != 0:
                return ""
            return r.std_out.decode("utf-8", "replace")
        except Exception as e:
            res.error = res.error or f"winrm exec failed: {e}"
            return ""

    osd = parse_win_os(run_ps(_PS_OS))
    if res.error and not osd:
        return res
    res.os_name = osd.get("caption")
    res.os_build = osd.get("build")
    res.os_cpe = os_cpe_windows(osd.get("caption", ""), osd.get("version", ""))
    res.hotfixes = parse_get_hotfix(run_ps(_PS_HOTFIX))
    res.packages = _enrich_packages(parse_win_software(run_ps(_PS_SOFTWARE)))
    return res


def scan_host(host: dict, cred: Credential,
              strict_host_keys: bool = False) -> CredResult:
    if cred.type == "ssh":
        return scan_ssh(host, cred, strict_host_keys=strict_host_keys)
    if cred.type == "winrm":
        return scan_winrm(host, cred, strict_host_keys=strict_host_keys)
    return CredResult(auth_method=cred.type, error=f"unknown cred type {cred.type}")


def deps_status() -> str:
    bits = []
    bits.append("paramiko " + ("ok" if _HAVE_PARAMIKO else "MISSING"))
    bits.append("pywinrm " + ("ok" if _HAVE_WINRM else "MISSING"))
    return ", ".join(bits)
