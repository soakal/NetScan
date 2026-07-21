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
import sys

from netscan.config import load_config, Config, SCAN_PROFILES


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
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
