# Running NetScan

## Easiest way — `run.bat` (Windows) / `run.sh` (Linux/macOS)

**Windows:** double-click `run.bat` in this folder.
**Linux/macOS:** run `./run.sh` from a terminal in this folder (make it
executable once with `chmod +x run.sh` if needed).

Both give you the same menu:

```
1. Scan your network
2. Serve the report (http://127.0.0.1:8000)
3. Scan, then serve the report
4. Demo mode (no network needed, sample data)
5. List scan profiles
0. Exit
```

- **Option 3** is the normal path: scan, then immediately view results.
- If `config.yaml` is missing, it's auto-created from `config.example.yaml` and
  the script pauses so you can edit your real targets before scanning.
- Press `Ctrl+C` to stop the report server (options 2/3/4) and return to the
  menu.
- On Linux/macOS, run the launcher as your normal user. If a profile needs
  privileged nmap features, elevate the **scan command only**:
  `sudo python3 run.py scan -c config.yaml`. Do not serve the report as root.

## Manual way (command line)

From this folder:

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

- Python 3.11+ with the dependencies installed: Flask, PyYAML, requests,
  pytest, `python-nmap`, and optionally `paramiko`/`pywinrm` (for
  credentialed scanning) — `pip install -r requirements.txt`.
- nmap (e.g. `winget install Insecure.Nmap` on Windows, or your distro's
  package) — gives accurate OS/service detection. Without it, NetScan falls
  back to a pure-Python scanner (still works, just less precise).
- Your own `config.yaml` (copied from `config.example.yaml`) with the
  subnets/hosts you are authorized to scan under `targets:`. It is
  gitignored — it holds your real network targets and stays local; keep
  machine-specific details there, not in tracked files.
- Sanity check: `python -m pytest -q` should pass cleanly.

## Installing on Linux

1. **Get the code** — clone or copy this repository onto the machine, e.g.
   `git clone <repo-url> netscan && cd netscan`.
2. **Install Python 3.11+** if it isn't already present:
   ```bash
   sudo apt install python3 python3-pip   # Debian/Ubuntu
   sudo dnf install python3 python3-pip   # RHEL/Fedora
   sudo pacman -S python python-pip       # Arch
   ```
3. **Install nmap** (recommended, for accurate OS/service detection):
   ```bash
   sudo apt install nmap   # Debian/Ubuntu
   sudo dnf install nmap   # RHEL/Fedora
   sudo pacman -S nmap     # Arch
   ```
4. **Install the Python dependencies**:
   ```bash
   python3 -m pip install -r requirements.txt
   ```
   If you skip this, `run.py`/`run.sh` will detect the missing package at
   startup, explain why it's needed, and prompt before installing it.
5. **Make the launcher executable** (one-time):
   ```bash
   chmod +x run.sh
   ```
6. **Create your config**:
   ```bash
   cp config.example.yaml config.yaml
   $EDITOR config.yaml   # set targets: to hosts/subnets you're authorized to scan
   ```
7. **Run it**: `./run.sh` → option 3 (scan, then serve), then open
   http://127.0.0.1:8000. For SYN scan / OS fingerprinting, run only the scan
   with elevation (`sudo python3 run.py scan -c config.yaml`), then serve as
   your normal user (`python3 run.py serve -c config.yaml`). This also ensures
   SSH keys and `known_hosts` resolve in the intended user's home directory.
8. **Automate re-scans** with a cron job or systemd timer, e.g. a crontab
   entry running `python3 run.py scan -c config.yaml` nightly — each run is
   its own record, and the **Scans** view in the report shows what opened,
   closed, or recurred between runs.

## First run checklist

1. Open `config.yaml` and confirm the `targets:` list is what you actually
   want scanned. Add anything under `exclude:` you want skipped (e.g. fragile
   devices, the scanner host itself).
2. Run `run.bat` (Windows) or `./run.sh` (Linux/macOS) → option 3 (scan, then
   serve), or the manual commands above.
3. Open http://127.0.0.1:8000 in a browser once the server starts.
4. Re-run a scan later (cron/systemd timer on Linux, Task Scheduler on
   Windows, or just re-run the launcher) — each scan is its own record, and
   the **Scans** view will show what opened, closed, or recurred between
   runs.
