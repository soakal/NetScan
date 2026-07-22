# Running NetScan

Pick your OS. Each section is self-contained: install, then run.

---

## Windows

### Install

1. **Get the code** — clone or copy this repository onto the machine, then open that folder.
2. **Install Python 3.11+** from https://www.python.org/downloads/  
   During setup, check **“Add python.exe to PATH”**.
3. **Install nmap** (recommended, for accurate OS/service detection):
   ```bat
   winget install Insecure.Nmap
   ```
   Or download from https://nmap.org/download.html
4. **Install the Python dependencies** (from a Command Prompt or PowerShell in this folder):
   ```bat
   python -m pip install -r requirements.txt
   ```
   That pulls in Flask, PyYAML, requests, python-nmap, pytest, and the
   optional credentialed-scan packages (paramiko, pywinrm).
   If you skip this, `run.bat` will detect a missing package at startup,
   explain why it's needed, and prompt before installing it.
5. **Create your config**:
   ```bat
   copy config.example.yaml config.yaml
   notepad config.yaml
   ```
   Set `targets:` to hosts/subnets you are authorized to scan.

### Run

1. Double-click **`run.bat`** in this folder.
2. Choose from the menu:
   ```
   1. Scan your network
   2. Serve the report (http://127.0.0.1:8000)
   3. Scan, then serve the report
   4. Demo mode (no network needed, sample data)
   5. List scan profiles
   0. Exit
   ```
3. **Option 3** is the normal path: scan, then open http://127.0.0.1:8000 in a browser.
4. Press `Ctrl+C` in the console to stop the report server (options 2/3/4) and return to the menu.

**Manual commands** (Command Prompt / PowerShell in this folder):

```bat
python run.py scan -c config.yaml
python run.py serve -c config.yaml
python run.py demo
python run.py profiles
```

**Re-scans:** use Task Scheduler, or just re-run `run.bat` → option 1 or 3. Each run is its own record; the **Scans** view shows what opened, closed, or recurred.

---

## Linux

### Install

1. **Get the code**:
   ```bash
   git clone <repo-url> netscan && cd netscan
   ```
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
   That pulls in Flask, PyYAML, requests, python-nmap, pytest, and the
   optional credentialed-scan packages (paramiko, pywinrm).
   If you skip this, `run.py`/`run.sh` will detect a missing package at
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

### Run

1. Start the launcher (sudo recommended so nmap can do SYN scan + OS detection):
   ```bash
   sudo ./run.sh
   ```
   Without sudo it still runs, with less accurate detection.
2. Choose from the menu:
   ```
   1. Scan your network
   2. Serve the report (http://127.0.0.1:8000)
   3. Scan, then serve the report
   4. Demo mode (no network needed, sample data)
   5. List scan profiles
   0. Exit
   ```
3. **Option 3** is the normal path: scan, then open http://127.0.0.1:8000 in a browser.
4. Press `Ctrl+C` to stop the report server (options 2/3/4) and return to the menu.

**Manual commands** (from this folder):

```bash
sudo python3 run.py scan -c config.yaml
python3 run.py serve -c config.yaml
python3 run.py demo
python3 run.py profiles
```

**Re-scans:** cron or a systemd timer running `python3 run.py scan -c config.yaml` nightly, or re-run `./run.sh` → option 1 or 3. Each run is its own record; the **Scans** view shows what opened, closed, or recurred.

---

## Notes (both platforms)

- `config.yaml` is gitignored — it holds your real targets and stays local.
- Without nmap, NetScan falls back to a pure-Python scanner (still works, less precise).
- Sanity check: `python -m pytest -q` (Windows) or `python3 -m pytest -q` (Linux) should pass.
- Get a free **NVD API key** (raises the rate limit 10×): https://nvd.nist.gov/developers/request-an-api-key
