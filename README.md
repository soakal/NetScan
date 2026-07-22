# NetScan

A lightweight, self-hosted internal vulnerability scanner with a web report —
think a small, open, Tenable-style tool you run on your own server against your
own network.

It discovers live hosts, fingerprints their services, correlates what it finds
against public vulnerability intelligence, and serves a report you can pivot
**by device**, **by vulnerability**, or **by weakness family**. Findings are
tracked across scans so you can confirm a patch actually landed.

> **Authorized use only.** Run NetScan only against networks and devices you own
> or have explicit written permission to test. Vulnerability scanning of systems
> you don't control may be illegal.

---

## What it does

- **Host discovery + service fingerprinting** via nmap (with a pure-Python
  fallback if nmap isn't installed).
- **CVE correlation** — maps detected products/versions (CPEs) to CVEs using the
  **NVD** API.
- **Exploited-in-the-wild flagging** via the **CISA KEV** catalog, including the
  ransomware-campaign flag and CISA's required remediation action + due date.
- **Exploit-likelihood scoring** via **EPSS** (FIRST.org) — the probability a CVE
  is exploited in the next 30 days. Used to compute a blended **priority** score
  so you fix what's actually likely to be used against you, not just what has the
  scariest CVSS.
- **Weakness classification** — every finding is tagged with its **CWE** and
  rolled up into an **OWASP Top 10:2025 family** (see "OpenHack" below).
- **Remediation steps** per finding, KEV-aware and product-aware, rendered as a
  checklist.
- **Patch verification** — findings present in a prior scan but gone in the
  current one are reported as **Resolved**; still-present ones as **Persisting**.
- **Scan history & trends** — every scan run is its own record (start/end time,
  hosts attempted/succeeded/failed). Each finding's lifecycle is tracked across
  scans (first seen, resolved, and **recurring** if it comes back after being
  resolved), and the **Scans** view shows Opened/Closed/Recurring counts per
  run so you can see remediation progress over time, not just a single
  snapshot.
- **Firmware advisories** for recognized network gear (switches/routers/APs/etc.):
  identifies the vendor and links its security-advisory page, flagged urgent when
  CVEs were correlated to the device.
- **Optional VirusTotal** IP-reputation enrichment.
- **Web report** with dashboard, devices, vulnerabilities, weaknesses, and scan
  history views, all drill-downable.

### On the "quiet scanning" goal

NetScan only ever performs **detection** — port/banner/version/OS fingerprinting.
It never runs exploit checks or attack payloads (no nmap `--script vuln`, no
exploitation), which is what would otherwise trip IDS/IPS and endpoint
protection. The default **`light`** profile additionally uses polite timing, a
small port set, and a capped packet rate to stay low-impact. Detection traffic
still appears in logs; it just looks like ordinary connections rather than
attacks.

### Credentialed (authenticated) scanning — quietest + most accurate

Instead of guessing software versions from network banners, NetScan can log into
hosts **you own** with a least-privilege account and read the real inventory.
This is the lowest-noise mode (a normal management login, not external probing)
and by far the most accurate.

- **SSH** (Linux/Unix/network gear, via `paramiko`): reads `/etc/os-release`,
  kernel (`uname -r`), and the package list (`dpkg-query`/`rpm -qa`). The OS,
  kernel, and a curated set of well-known packages (OpenSSH, OpenSSL, Apache,
  nginx, …) are mapped to CPEs and correlated against NVD.
- **WinRM** (Windows, via `pywinrm`): reads the OS caption/build
  (`Win32_OperatingSystem`), **installed hotfixes** (`Get-HotFix`), and installed
  software (registry uninstall hives). The hotfix list is shown on the device
  page so you can confirm a specific KB is present after patching.

Everything run on the target is **read-only**; nothing is changed. Commands used:
`cat /etc/os-release`, `uname -r`, `dpkg-query -W`/`rpm -qa` over SSH;
`Get-CimInstance Win32_OperatingSystem`, `Get-HotFix`, and a read of the
Uninstall registry keys over WinRM.

Enable it in `config.yaml` (`credentialed: true` + a `credentials:` block) and
install the optional deps: `pip install paramiko pywinrm`. Use a dedicated
read-only service account — not a domain admin — and keep the config file out of
version control.

By default, host identity isn't verified (a first connection to a new host
has no known_hosts entry to check against), so credentialed scanning prints a
one-time warning that a MITM could capture the scan credential. Set
`strict_host_keys: true` to enforce verification instead — unknown or changed
hosts then fail their credentialed scan rather than being trusted silently.

### Accurate matching backends: OVAL (Linux) + MSRC (Windows)

Credentialed scanning gets much more accurate when the package/patch inventory is
matched against authoritative vendor data instead of generic CPEs:

- **OVAL (Linux)** — distros publish OVAL feeds stating, per release, the
  *fixed* version of each package for each CVE. NetScan downloads the feed for
  the host's distro (Ubuntu/Debian/RHEL family), then compares each installed
  package to the fixed version using the distro's real version ordering (a
  correct `dpkg`/`rpm` version comparator). Because it compares against the
  distro's fixed build, it's **backport-aware** — no more false positives from a
  patched-but-old-looking version string. Findings are tagged source `oval` and
  carry an "upgrade to <fixed>" step.
- **MSRC (Windows)** — Microsoft's monthly CVRF documents map each CVE to the KB
  that fixes it for each product. NetScan pulls the recent months, matches the
  host's OS to the right product, and compares the **installed hotfix list**
  against the fixing KBs — accounting for **supersedence** (a cumulative update
  covers the KBs it supersedes). The result is a precise list of CVEs the host is
  *missing the patch for*, tagged source `msrc`, plus a count of CVEs already
  covered.

Both are on by default when credentialed (`oval_matching` / `msrc_matching`), need
no API key, and cache their feeds. When a backend authoritatively handles a host,
NetScan skips imprecise OS/package CPE matching for that host (it still correlates
real listening network services by CPE). The detection source is shown on each
finding and on the CVE detail page.

Accuracy notes: OVAL covers the distros listed in `oval.py` (extend
`OVAL_SOURCES` for more); MSRC product matching is by normalized OS-caption
substring and supersedence data comes from the CVRF, so pull several months
(`msrc_months`) for best coverage.

---

## How this relates to Hadrian OpenHack

[OpenHack](https://github.com/hadriansecurity/OpenHack) is a different kind of
tool: it's an **AI-agent-driven whitebox source-code review** system. It clones a
git repository and runs reconnaissance/expert/triage agents (in a model harness
like Claude Code) to find code-level bugs, organized around the **OWASP Top
10:2025** families and **MITRE CWE**, optionally enriched with Semgrep rules. It
uses no CVE database.

So most of OpenHack doesn't map onto a black-box network scanner — it needs
source code and an LLM. What *does* port over cleanly is its **classification
lens**: organizing findings by root-cause weakness family rather than just
listing CVEs. NetScan adopts that idea (the **Weaknesses** view, CWE + OWASP
2025 families, modeled on OpenHack's expert registry) and pairs it with **EPSS**
for exploit-likelihood prioritization — both of which are distinct from the
CVE/KEV/NVD/VirusTotal sources in the original design.

If you also want to review your *application source code* the way OpenHack does,
run OpenHack (or Semgrep) directly — it's complementary to network scanning, not
a substitute.

---

## Install

**Windows:**
```bash
python3 -m pip install -r requirements.txt
winget install Insecure.Nmap   # recommended, for OS detection + CPE-based CVE matching
```

**Linux/macOS:**
```bash
chmod +x setup.sh
./setup.sh
```
`setup.sh` installs the Python dependencies into a project-local `.venv`
(avoiding the "externally-managed-environment" error modern Debian/Ubuntu
throws on a plain `pip install`), installs `nmap` if it's missing, and offers
to grant `nmap` the capability it needs for SYN scans/service detection
without `sudo`. OS detection specifically still requires `sudo` — nmap
enforces that regardless of capabilities. See [RUNNING.md](RUNNING.md) for
details.

See [RUNNING.md](RUNNING.md) for a fuller setup walkthrough, including the
double-click `run.bat` launcher on Windows and the `run.sh` equivalent on
Linux/macOS.

If you skip this step, NetScan detects a missing Python dependency at
startup, explains what it is and why it's needed, shows the exact
`pip install` command, and asks before running it (never silently — a
security tool installing software without asking would be a red flag in
itself). Pass `--auto-install` to skip the prompt for scripted/unattended
runs. This only ever covers Python packages from `requirements.txt`; nmap
itself is never auto-installed (see the warning `scan` prints if it's
missing, which includes the right install command for your OS).

Get a free **NVD API key** (raises the rate limit 10x — strongly recommended for
anything bigger than a handful of hosts):
https://nvd.nist.gov/developers/request-an-api-key

## Configure

```bash
cp config.example.yaml config.yaml
$EDITOR config.yaml          # set `targets:` and, ideally, nvd_api_key
```

Keys can also come from the environment: `NETSCAN_NVD_API_KEY`,
`NETSCAN_VT_API_KEY`.

## Run

**Windows:** double-click `run.bat` for a menu (scan / serve / demo /
profiles) instead of typing commands.
**Linux/macOS:** run `./run.sh` (`chmod +x run.sh` once first) for the same
menu. See [RUNNING.md](RUNNING.md) for a full install/run walkthrough,
including a step-by-step Linux install. Everything below also works from a
terminal on any platform.

```bash
# 1) scan — on Linux/macOS, ./setup.sh grants nmap the capability it needs
#    for SYN scan + service detection without sudo. OS detection specifically
#    still requires sudo (nmap enforces this regardless of capabilities);
#    without it, OS fingerprinting is skipped but the rest of the scan
#    still runs (see RUNNING.md):
sudo python run.py scan -c config.yaml

# 2) serve the report
python run.py serve -c config.yaml
#    -> http://127.0.0.1:8000

# list scan profiles (light / standard / thorough)
python run.py profiles
```

Re-run `scan` on a schedule (cron/systemd timer). Each run is a snapshot; the
report diffs consecutive runs to show what got fixed.

### Try the UI with no network

```bash
python run.py demo      # seeds synthetic findings into demo.db
python run.py serve     # explore the dashboard offline (reads demo.db)
```

Demo mode always writes to its own `demo.db`, never `netscan.db` — synthetic
data can't get mixed into your real scan history.

---

## Data sources

| Source | What it provides | Key needed |
|---|---|---|
| NVD CVE API 2.0 | CVEs per CPE, CVSS, CWE, references | optional (recommended) |
| CISA KEV | exploited-in-the-wild flag, ransomware flag, required action | no |
| EPSS (FIRST.org) | 30-day exploit probability | no |
| MITRE CWE + OWASP 2025 | weakness taxonomy (bundled mapping) | no |
| VirusTotal API v3 | IP reputation (optional) | optional |
| SSH / WinRM (credentialed) | real OS build, packages, installed KBs | host creds you own |
| Distro OVAL feeds | backport-aware Linux package CVEs (fixed versions) | no |
| Microsoft MSRC (CVRF) | Windows CVE→KB mapping, missing-patch detection | no |

## Layout

```
run.py                     CLI: scan / serve / demo / profiles
run.bat                    Windows double-click launcher (menu over run.py)
run.sh                     Linux/macOS launcher, same menu as run.bat
setup.sh                   Linux/macOS one-time setup (venv, deps, nmap)
RUNNING.md                 setup/run walkthrough (Windows + Linux install)
LICENSE                    proprietary, all rights reserved (Copyright VRSI)
config.example.yaml        copy to config.yaml
netscan/
  config.py                config + scan profiles + credentials
  scanner.py               discovery + fingerprinting (nmap / socket fallback)
  credentialed.py          authenticated SSH/WinRM inventory (read-only)
  oval.py                  distro OVAL feeds + dpkg/rpm version comparison (Linux)
  msrc.py                  Microsoft CVRF parsing + CVE→KB correlation (Windows)
  enrich.py                KEV, NVD, EPSS, VirusTotal clients (+ disk cache)
  taxonomy.py              CWE names + OWASP Top 10:2025 mapping
  remediation.py           per-finding remediation steps
  firmware.py              network-device firmware advisory framework
  correlate.py             orchestrates a full scan + cross-scan diff
  db.py                    SQLite persistence
  demo.py                  synthetic data seeder (writes demo.db, not netscan.db)
  web/                     Flask report (app.py + templates/)
tests/                     pytest suite
```

## Limitations

- Unauthenticated, black-box scanning: less accurate than credentialed scanning,
  and version-only CVE matching can produce false positives (a backported fix may
  not change the banner version). Treat findings as leads to confirm.
- Modern, well-configured Windows hosts often don't expose detailed version
  banners over SMB/RPC/RDP at all, even with the `thorough` profile — nmap may
  report the port open with no usable version string, which means nothing to
  correlate against NVD. Zero findings on such a host is a real "couldn't
  determine a version," not a confirmed "no vulnerabilities." Credentialed
  scanning (above) reads the actual installed-hotfix list instead of guessing
  from banners, and is the only way to get a definitive answer on those hosts.
- The OWASP/CWE family mapping and CWE name table are curated best-effort, not an
  authoritative MITRE/OWASP mapping.
- Firmware checks point you at vendor advisories rather than auto-comparing
  versions (vendor feeds vary too much to automate reliably out of the box).
- This is a self-hosted tool, not an audited security product. Verify before
  acting.

Proprietary — Copyright (c) 2026 VRSI. All rights reserved. See [LICENSE](LICENSE).
