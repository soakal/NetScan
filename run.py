#!/usr/bin/env python3
"""NetScan command-line entrypoint.

    python run.py scan   -c config.yaml      # discover + correlate + store
    python run.py serve  -c config.yaml      # launch the web report
    python run.py demo                       # seed synthetic data (no network)

`scan` then `serve` is the normal flow. Schedule `scan` on a cron/timer to keep
the report current and to drive the resolved/persisting diff across scans.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from netscan.config import load_config, Config, SCAN_PROFILES

_REQUIREMENTS = Path(__file__).resolve().parent / "requirements.txt"

# The only names we'll ever offer to auto-install: top-level modules from
# requirements.txt, each with a plain-English reason a non-developer can
# understand. A ModuleNotFoundError for anything else (e.g. "netscan.web",
# from a broken/incomplete source tree) is a real bug, not a missing
# dependency -- `pip install -r requirements.txt` can't fix that, and
# offering to "install" it would be actively misleading.
_INSTALLABLE_DEPS = {
    "flask": "runs the web report/dashboard (the `serve` command)",
    "requests": "talks to the CVE/threat-intel APIs (NVD, KEV, EPSS, "
                "VirusTotal) used by `scan`",
    "yaml": "reads your config.yaml file (this is the PyYAML package)",
    "nmap": "the Python wrapper NetScan uses to drive the nmap scan engine "
            "(this is the python-nmap package, not nmap itself)",
    "paramiko": "SSH credentialed scanning (Linux/Unix/network gear)",
    "winrm": "WinRM credentialed scanning (Windows) (this is the pywinrm "
             "package)",
}


def _stdin_is_tty() -> bool:
    return sys.stdin.isatty()


def _offer_dependency_install(module_name: str, assume_yes: bool) -> bool:
    """Ask before installing a missing required dependency. Returns True
    only if pip actually ran and exited 0 -- the caller retries the import
    exactly once after that, never loops."""
    reason = _INSTALLABLE_DEPS.get(module_name)
    if reason is None:
        return False  # not a known top-level dependency -- don't guess
    if not _REQUIREMENTS.exists():
        return False

    command = f"{sys.executable} -m pip install -r {_REQUIREMENTS}"
    print(f"error: missing required dependency {module_name!r} -- "
          f"{reason}.", file=sys.stderr)
    print(f"Would run: {command}", file=sys.stderr)

    if assume_yes:
        print("--auto-install passed, installing without prompting.",
              file=sys.stderr)
    else:
        if not _stdin_is_tty():
            print("Run: pip install -r requirements.txt", file=sys.stderr)
            return False
        answer = input("Install it now? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Not installing. Run: pip install -r requirements.txt",
                  file=sys.stderr)
            return False

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(_REQUIREMENTS)],
        )
    except OSError as e:
        print(f"error: could not run pip: {e}", file=sys.stderr)
        return False
    if result.returncode != 0:
        print(f"error: automatic install failed (pip exited {result.returncode}); "
              f"run manually: pip install -r requirements.txt", file=sys.stderr)
        return False
    return True


def cmd_scan(args) -> int:
    cfg = load_config(args.config)
    from netscan.correlate import run_scan
    scan_id = run_scan(cfg)
    print(f"Scan #{scan_id} complete. View it with: python run.py serve -c {args.config}")
    return 0


# Hosts on which the Werkzeug debugger may safely listen. --debug enables the
# interactive debugger, which is an arbitrary-code-execution endpoint for
# anyone who can reach it, so it must never be bound to a network-facing host.
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def cmd_serve(args) -> int:
    # No -c/--config given means the no-network demo trial (see `demo`
    # below) -- point at demo.db to match, never at a real scan's netscan.db.
    cfg = load_config(args.config) if args.config else Config(db_path="demo.db")
    if args.debug and cfg.web_host not in _LOCAL_HOSTS:
        print(
            f"error: refusing to start: --debug enables the Werkzeug interactive "
            f"debugger (remote code execution for anyone who can reach it), but "
            f"web_host is {cfg.web_host!r}, which is not localhost. Set "
            f"web_host: 127.0.0.1 in the config, or drop --debug.",
            file=sys.stderr,
        )
        return 2
    from netscan.web import create_app
    app = create_app(cfg.db_path)
    print(f"Serving report at http://{cfg.web_host}:{cfg.web_port}")
    app.run(host=cfg.web_host, port=cfg.web_port, debug=args.debug)
    return 0


def cmd_demo(args) -> int:
    """Seed the DB with synthetic findings so you can explore the UI offline."""
    from netscan.demo import seed
    # Defaults to its own demo.db, never netscan.db -- demo data must never
    # mix with a real scan's history (finding lifecycle, resolved/recurring).
    db_path = args.db or "demo.db"
    n = seed(db_path)
    print(f"Seeded demo data into {db_path} ({n} findings). "
          f"Now run: python run.py serve")
    return 0


def cmd_profiles(_args) -> int:
    print("Available scan profiles:\n")
    for name, p in SCAN_PROFILES.items():
        print(f"  {name:10s} {p['description']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="netscan", description=__doc__)
    parser.add_argument(
        "--auto-install", action="store_true",
        help="if a required dependency is missing, install it without "
             "prompting (for scripted/unattended use)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="run a scan and store results")
    p_scan.add_argument("-c", "--config", required=True)
    p_scan.set_defaults(func=cmd_scan)

    p_serve = sub.add_parser("serve", help="serve the web report")
    p_serve.add_argument("-c", "--config")
    p_serve.add_argument("--debug", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    p_demo = sub.add_parser("demo", help="seed synthetic data (no network)")
    p_demo.add_argument("--db")
    p_demo.set_defaults(func=cmd_demo)

    p_prof = sub.add_parser("profiles", help="list scan profiles")
    p_prof.set_defaults(func=cmd_profiles)

    args = parser.parse_args()
    offered_install = False
    while True:
        try:
            return args.func(args)
        except (FileNotFoundError, ValueError, RuntimeError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        except ModuleNotFoundError as e:
            # A required (non-optional) dependency is missing -- e.g. flask
            # for `serve`, requests for `scan`. Offer to install it (once)
            # instead of just failing, but never for an internal netscan.*
            # import (that's a broken source tree, not a missing package --
            # pip can't fix it, and claiming it can would be misleading).
            if (not offered_install and e.name
                    and not e.name.startswith("netscan")
                    and _offer_dependency_install(e.name, args.auto_install)):
                offered_install = True
                continue
            print(f"error: missing required dependency {e.name!r}. "
                  f"Run: pip install -r requirements.txt", file=sys.stderr)
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
