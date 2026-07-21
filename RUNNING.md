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

## First run checklist

1. Open `config.yaml` and confirm the `targets:` list is what you actually
   want scanned. Add anything under `exclude:` you want skipped (e.g. fragile
   devices, the scanner host itself).
2. Run `run.bat` → option 3 (scan, then serve), or the manual commands above.
3. Open http://127.0.0.1:8000 in a browser once the server starts.
4. Re-run a scan later (cron/Task Scheduler, or just `run.bat` again) — each
   scan is its own record, and the **Scans** view will show what opened,
   closed, or recurred between runs.
