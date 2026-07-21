# Running NetScan

## Easiest way — `run.bat`

Double-click `run.bat` in this folder. You'll get a menu:

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

## Current setup on this machine

- Python 3.14, with all dependencies installed: Flask, PyYAML, requests,
  pytest, `python-nmap`, and the optional `paramiko`/`pywinrm` (for
  credentialed scanning).
- nmap 7.80 installed via `winget install Insecure.Nmap` — gives accurate
  OS/service detection. Without it, NetScan falls back to a pure-Python
  scanner (still works, just less precise).
- `config.yaml` targets `10.10.10.0/23` (Ethernet) and `192.168.200.0/24`
  (Ethernet 2), on the `light` (quiet, detection-only) scan profile. It is
  gitignored — it holds your real network targets and stays local.
- 18/18 tests pass (`python -m pytest -q`).

## First run checklist

1. Open `config.yaml` and confirm the `targets:` list is what you actually
   want scanned. Add anything under `exclude:` you want skipped (e.g. fragile
   devices, the scanner host itself).
2. Run `run.bat` → option 3 (scan, then serve), or the manual commands above.
3. Open http://127.0.0.1:8000 in a browser once the server starts.
4. Re-run a scan later (cron/Task Scheduler, or just `run.bat` again) — each
   scan is its own record, and the **Scans** view will show what opened,
   closed, or recurred between runs.
