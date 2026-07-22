# Running NetScan

## Quick start

**Linux/macOS:**
```bash
chmod +x setup.sh run.sh
./setup.sh           # one-time: creates .venv, installs dependencies, sets up nmap
sudo ./run.sh        # every time: launches the app (sudo enables OS detection)
```

> **Use `sudo ./run.sh`** (or the "NetScan" desktop shortcut `setup.sh`
> creates, which does this for you) **for `standard`/`thorough` scans.**
> Without root, scans still work but **silently skip OS detection** — nmap's
> capabilities (from `setup.sh`) cover SYN scan/service detection but are
> not enough for OS fingerprinting specifically. Details in "About `sudo`"
> below.

**Windows:** double-click `run.bat`. No setup step needed — Windows doesn't
have the restriction `setup.sh` works around (see "Why setup.sh exists"
below).

Both launchers show the same menu:

```
1. Scan your network
2. Serve the report (http://127.0.0.1:8000)
3. Scan, then serve the report
4. Demo mode (no network needed, sample data)
5. List scan profiles
0. Exit
```

- **Option 3** is the normal path: scan, then immediately view results at
  http://127.0.0.1:8000.
- If `config.yaml` is missing, it's created automatically from
  `config.example.yaml`, and the launcher pauses so you can set your real
  `targets:` before scanning.
- Press `Ctrl+C` to stop the report server (options 2/3/4) and return to the
  menu.

## First run checklist

1. **Linux/macOS only:** run `./setup.sh` once. Windows doesn't need this.
2. Open `config.yaml` and set `targets:` to the hosts/subnets you're
   authorized to scan. Add anything you want skipped under `exclude:` (e.g.
   fragile devices, the scanner host itself).
3. Run **`sudo ./run.sh`** (or `run.bat` on Windows) → option 3.
4. Open http://127.0.0.1:8000 once the server starts.
5. Re-run scans later (cron/systemd timer on Linux, Task Scheduler on
   Windows, or just re-run the launcher) — each scan is its own record, and
   the **Scans** view shows what opened, closed, or recurred between runs.

## Why `setup.sh` exists (Linux/macOS)

Modern Debian/Ubuntu refuse a plain `pip install` against the system Python
("externally-managed-environment", PEP 668). `setup.sh` avoids this by
installing everything into a project-local `.venv` instead. It also:

- Installs the `nmap` package if it's missing (optional — without it,
  NetScan falls back to a pure-Python scanner with less accurate
  fingerprinting).
- Offers to grant `nmap` a Linux capability (`setcap cap_net_raw,cap_net_admin`)
  so it can do accurate SYN scans and service/version detection **as your
  normal user, no `sudo` needed**. This does **not** cover OS detection
  (`-O`) — nmap hard-requires actual root for that specifically, regardless
  of capabilities (a real nmap limitation, not something `setcap` can work
  around). See "About sudo" below for what that means in practice.
- Creates `config.yaml` from `config.example.yaml` if you don't have one yet.

Safe to re-run any time (e.g. after an OS/nmap upgrade strips the
capability). Pass `-y`/`--yes` to accept every prompt non-interactively.

`run.sh` auto-detects and uses `.venv` if `setup.sh` created one — you never
need to activate it yourself.

## About `sudo`

Whether you need `sudo` depends on what you're scanning with:

- **`light` profile:** never needs `sudo`. It doesn't use OS detection at
  all, so nmap's capability grant (from `./setup.sh`) is all it needs.
- **`standard`/`thorough` profiles:** nmap's capability grant is enough for
  the SYN scan and service/version detection — but **not** for OS
  fingerprinting. Without real root, NetScan detects this, skips OS
  detection with a one-line warning, and still returns full port/service/CVE
  results. **To also get OS detection, you need `sudo ./run.sh`** — there's
  no way around this; it's a hard requirement nmap itself enforces
  (`setcap` capabilities can't satisfy it, confirmed directly against nmap's
  behavior).

If you do run `sudo ./run.sh`, it takes care of the two problems that
normally come with running as root:

- **File ownership:** anything the session creates (`netscan.db`,
  `.netscan_cache/`, etc.) gets automatically handed back to your normal
  user account when `run.sh` exits, so you're never locked out of deleting
  or editing your own files afterward.
- **Missing dependencies:** `sudo` normally resets `$PATH`, which would make
  it use the system Python instead of `.venv` and fail with confusing
  "module not found" errors. `run.sh` avoids this by calling `.venv/bin/python`
  directly, by absolute path, regardless of `sudo`.

This protection only applies to `run.sh` itself. If you run manual commands
with `sudo` (not through `run.sh`), use the `.venv` interpreter by absolute
path to avoid the `$PATH` problem:
```bash
sudo ./.venv/bin/python run.py scan -c config.yaml
```

## Manual way (command line)

From this folder (Linux/macOS: activate `.venv` first, or call
`.venv/bin/python` directly):

```bash
# scan your network
python run.py scan -c config.yaml

# view the report at http://127.0.0.1:8000
python run.py serve -c config.yaml
```

Try it with no real network scan first:

```bash
python run.py demo
python run.py serve
```

List available scan profiles (`light` / `standard` / `thorough`):

```bash
python run.py profiles
```

## Setup requirements

- **Python 3.11+** with dependencies installed: Flask, PyYAML, requests,
  pytest, `python-nmap`, and optionally `paramiko`/`pywinrm` (for
  credentialed scanning).
  - Linux/macOS: `./setup.sh` handles this (see above). Manual alternative:
    ```bash
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
    ```
  - Windows: `pip install -r requirements.txt` works directly.
- **nmap** (optional but recommended) — `winget install Insecure.Nmap` on
  Windows, or your distro's package on Linux/macOS (`setup.sh` offers to
  install it). Without it, NetScan falls back to a pure-Python scanner —
  still works, just less precise.
- **Your own `config.yaml`** (copied from `config.example.yaml`, or created
  automatically) with `targets:` set to what you're authorized to scan. It's
  gitignored — it holds your real network details and stays local.
- Sanity check: `python -m pytest -q` should pass cleanly.

## Installing on Linux (from scratch)

1. **Get the code**: `git clone <repo-url> netscan && cd netscan`.
2. **Install Python 3.11+** if needed:
   ```bash
   sudo apt install python3   # Debian/Ubuntu
   sudo dnf install python3   # RHEL/Fedora
   sudo pacman -S python      # Arch
   ```
3. **Run setup**:
   ```bash
   chmod +x setup.sh run.sh
   ./setup.sh
   ```
4. **Set your targets**: `$EDITOR config.yaml`.
5. **Run it**: `./run.sh` → option 3, then open http://127.0.0.1:8000.
6. **Automate re-scans** with cron/systemd, e.g. a nightly crontab entry:
   ```
   /path/to/netscan/.venv/bin/python /path/to/netscan/run.py scan -c /path/to/netscan/config.yaml
   ```
   Use the `.venv` interpreter and full paths — cron's minimal `$PATH` won't
   find a bare `python3` with the right packages installed.
