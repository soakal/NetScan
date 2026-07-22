"""Configuration loading and scan profiles.

Config is YAML. A minimal config only needs `targets`. Everything else has
sane defaults. API keys can also come from environment variables so you don't
have to commit them:

    NETSCAN_NVD_API_KEY
    NETSCAN_VT_API_KEY
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# Hard cap on IP expansion for CIDR/range targets. A typo like /8 would
# otherwise materialize millions of addresses and hang the scanner.
MAX_TARGET_HOSTS = 65536

# Scan profiles control how aggressive (and how noisy) the scan is.
#
# The whole point of the "light"/default profile is to stay quiet: polite
# timing, a small port set, gentle version probing, and crucially NO
# exploit/NSE "vuln" scripts. We only ever *detect* (banner/version/OS), never
# *exploit*, which is what keeps the scan from tripping IDS/IPS and EDR the way
# active exploitation attempts would. Detection traffic still shows up in logs,
# but it looks like ordinary connection attempts rather than attacks.
SCAN_PROFILES: dict[str, dict[str, Any]] = {
    # Quietest. Recommended default. Top ~100 ports, polite timing, low rate.
    "light": {
        # NOTE: --host-timeout must comfortably exceed how long `-sV` version
        # detection takes over --top-ports 100 at -T2's polite timing. When the
        # host timeout fires mid-version-scan, nmap DISCARDS the host's results
        # entirely (reports 0 open ports), which silently turns "up but slow"
        # hosts into "no services" -> nothing to correlate -> zero findings.
        # 90s was too short (version detection alone needs ~100s+ per host), so
        # this is 5m to match `standard` and leave ample headroom.
        "nmap_args": "-sV --version-intensity 2 -T2 --top-ports 100 "
                     "--max-rate 50 --max-retries 1 --host-timeout 5m",
        "os_detection": False,
        "description": "Quiet, top-100 ports, polite timing, low packet rate.",
    },
    # Balanced. Top 1000 ports, light OS detection.
    "standard": {
        "nmap_args": "-sV -T3 --top-ports 1000 --max-retries 2 --host-timeout 5m",
        "os_detection": True,
        "description": "Top-1000 ports with light OS detection.",
    },
    # Loud. Full version detection over many ports + OS detection. Will be
    # noticed by a SOC. Use only with authorization and a maintenance window.
    "thorough": {
        "nmap_args": "-sV --version-all -T4 -p- --max-retries 2 --host-timeout 20m",
        "os_detection": True,
        "description": "All ports, full version detection, OS detection. Noisy.",
    },
}

# Ports probed by the built-in pure-Python fallback scanner (used only when
# nmap is unavailable). Kept small and common on purpose.
FALLBACK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 631, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8008,
    8080, 8443, 9100,
]


@dataclass
class Credential:
    """A credential set for authenticated (credentialed) scanning.

    Credentials are provisioned and owned by the operator (typically a dedicated,
    least-privilege read-only service account). They are used only to log in over
    the host's normal management protocol and run read-only inventory queries —
    never to change anything on the target.

    `match` is a list of CIDRs / IP globs; a host uses the first credential whose
    match contains it. An empty match list applies to every host of that type.
    Prefer `password_env` / SSH keys over inline passwords, and keep config.yaml
    out of version control (chmod 600).
    """
    name: str
    type: str                       # "ssh" | "winrm"
    username: str
    password: str | None = None
    key_file: str | None = None     # ssh only
    port: int | None = None
    scheme: str = "https"           # winrm: https (5986) or http (5985)
    match: list[str] = field(default_factory=list)

    def default_port(self) -> int:
        if self.port:
            return self.port
        if self.type == "ssh":
            return 22
        return 5986 if self.scheme == "https" else 5985


@dataclass
class Config:
    targets: list[str] = field(default_factory=list)
    scan_profile: str = "light"
    exclude: list[str] = field(default_factory=list)

    nvd_api_key: str | None = None
    vt_api_key: str | None = None
    vt_check_host_ips: bool = False  # off by default: VT IP lookups touch a 3rd party

    # Credentialed (authenticated) scanning: log into hosts you own and read an
    # accurate software/patch inventory. Quietest + most accurate scan mode.
    credentialed: bool = False
    credentials: list[Credential] = field(default_factory=list)
    # Verify host identity during credentialed scans. On by default (SSH:
    # known_hosts required; WinRM: valid TLS cert required). Set false only for
    # a first lab/fleet scan when you have not provisioned host keys/certs yet —
    # that mode auto-accepts SSH keys and skips WinRM TLS validation, which a
    # MITM on the scan path could abuse to capture the scan credential.
    strict_host_keys: bool = True

    # Accurate credentialed matching backends:
    #   OVAL  — distro security feeds for Linux (backport-aware, low FP)
    #   MSRC  — Microsoft CVE->KB data for Windows (missing-patch detection)
    oval_matching: bool = True
    msrc_matching: bool = True
    msrc_months: int = 3              # how many recent patch-Tuesday months to pull
    msrc_api_key: str | None = None

    db_path: str = "netscan.db"
    cache_dir: str = ".netscan_cache"

    # Re-pull the KEV catalog / NVD results if the cache is older than this.
    kev_cache_hours: int = 24
    nvd_cache_hours: int = 168  # a week; CVE-per-CPE results change slowly

    web_host: str = "127.0.0.1"
    web_port: int = 8000

    @property
    def profile(self) -> dict[str, Any]:
        if self.scan_profile not in SCAN_PROFILES:
            raise ValueError(
                f"Unknown scan_profile {self.scan_profile!r}. "
                f"Choose one of: {', '.join(SCAN_PROFILES)}"
            )
        return SCAN_PROFILES[self.scan_profile]


def _as_bool(value: Any, default: bool, field_name: str) -> bool:
    """Parse YAML bools without the `bool("false") is True` footgun."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "1", "on"):
            return True
        if v in ("false", "no", "0", "off", ""):
            return False
    raise ValueError(
        f"config field {field_name!r}: expected a boolean, got {value!r}"
    )


def _as_str_list(value: Any, field_name: str) -> list[str]:
    """Normalize targets/exclude to a list of strings.

    A bare scalar (common YAML mistake: `targets: 10.0.0.1`) becomes a
    one-element list. Rejects values that look like nmap option injection.
    """
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, list):
        items = value
    else:
        raise ValueError(
            f"config field {field_name!r}: expected a list of strings, got "
            f"{type(value).__name__}"
        )
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError(
                f"config field {field_name!r}: each entry must be a string, "
                f"got {item!r}"
            )
        s = item.strip()
        if not s:
            continue
        if s.startswith("-"):
            raise ValueError(
                f"config field {field_name!r}: refusing {s!r} — values must not "
                f"start with '-' (would be passed as nmap options)"
            )
        out.append(s)
    return out


def load_config(path: str | os.PathLike | None) -> Config:
    data: dict[str, Any] = {}
    if path:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        if yaml is None:
            raise RuntimeError("PyYAML is required to read config files. pip install pyyaml")
        data = yaml.safe_load(p.read_text()) or {}
        if not isinstance(data, dict):
            raise ValueError("config root must be a mapping/object")

    cfg = Config(
        targets=_as_str_list(data.get("targets", []), "targets"),
        scan_profile=data.get("scan_profile", "light"),
        exclude=_as_str_list(data.get("exclude", []), "exclude"),
        nvd_api_key=data.get("nvd_api_key") or os.environ.get("NETSCAN_NVD_API_KEY"),
        vt_api_key=data.get("vt_api_key") or os.environ.get("NETSCAN_VT_API_KEY"),
        vt_check_host_ips=_as_bool(data.get("vt_check_host_ips"), False, "vt_check_host_ips"),
        credentialed=_as_bool(data.get("credentialed"), False, "credentialed"),
        credentials=_parse_credentials(data.get("credentials", []) or []),
        strict_host_keys=_as_bool(
            data.get("strict_host_keys"), True, "strict_host_keys"
        ),
        oval_matching=_as_bool(data.get("oval_matching"), True, "oval_matching"),
        msrc_matching=_as_bool(data.get("msrc_matching"), True, "msrc_matching"),
        msrc_months=int(data.get("msrc_months", 3)),
        msrc_api_key=data.get("msrc_api_key") or os.environ.get("NETSCAN_MSRC_API_KEY"),
        db_path=data.get("db_path", "netscan.db"),
        cache_dir=data.get("cache_dir", ".netscan_cache"),
        kev_cache_hours=int(data.get("kev_cache_hours", 24)),
        nvd_cache_hours=int(data.get("nvd_cache_hours", 168)),
        web_host=data.get("web_host", "127.0.0.1"),
        web_port=int(data.get("web_port", 8000)),
    )
    # Validate profile eagerly.
    _ = cfg.profile
    return cfg


def _parse_credentials(items: Any) -> list[Credential]:
    if not items:
        return []
    if not isinstance(items, list):
        raise ValueError("config field 'credentials': expected a list")
    creds: list[Credential] = []
    for it in items:
        if not isinstance(it, dict):
            raise ValueError("each credentials entry must be a mapping")
        ctype = it.get("type")
        if ctype not in ("ssh", "winrm"):
            raise ValueError(f"credential {it.get('name')!r}: type must be ssh or winrm")
        # Password resolution order: inline -> env-var name in password_env.
        password = it.get("password")
        if not password and it.get("password_env"):
            password = os.environ.get(it["password_env"])
        key_file = it.get("key_file")
        if key_file:
            key_file = os.path.expanduser(str(key_file))
        match = it.get("match", []) or []
        if isinstance(match, str):
            match = [match]
        if not isinstance(match, list):
            raise ValueError(
                f"credential {it.get('name')!r}: match must be a list of strings"
            )
        creds.append(Credential(
            name=it.get("name", ctype),
            type=ctype,
            username=it.get("username", ""),
            password=password,
            key_file=key_file,
            port=it.get("port"),
            scheme=it.get("scheme", "https"),
            match=[str(m) for m in match],
        ))
    return creds
