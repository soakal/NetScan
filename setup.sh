#!/usr/bin/env bash
# NetScan first-time setup for Linux/macOS.
#
# Creates a project-local virtual environment (./.venv), installs the Python
# dependencies into it, and offers to install/configure nmap so scans get
# accurate SYN-scan + service detection without sudo (OS detection still
# needs sudo regardless -- see RUNNING.md). Safe to re-run at any time.
set -uo pipefail
cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"

# Running from a Trash/Recycle-bin copy is never intentional -- see run.sh
# for the full rationale. Hard-refuse rather than warn.
case "$SCRIPT_DIR" in
    *"/.local/share/Trash/"*|*"/.Trash/"*|*"/.Trash-"*)
        echo "ERROR: this is a DELETED copy sitting in Trash/Recycle Bin:" >&2
        echo "  $SCRIPT_DIR" >&2
        echo "Find and run the real app folder instead (e.g. ~/Documents/netscan-app)." >&2
        exit 1
        ;;
esac
echo "Running from: $SCRIPT_DIR"
echo

VENV_DIR="$SCRIPT_DIR/.venv"
VENV_PY="$VENV_DIR/bin/python"
ASSUME_YES=0
PKG_MGR=""
OS_KIND=""
SYS_PYTHON=""
PY_MM=""

STATUS_VENV="skipped"
STATUS_DEPS="skipped"
STATUS_NMAP="skipped"
STATUS_CAPS="skipped"
STATUS_CONFIG="skipped"
STATUS_DESKTOP="skipped"
STATUS_SMOKE="skipped"

say()  { echo "==> $*"; }
warn() { echo "WARNING: $*" >&2; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        -y|--yes)
            ASSUME_YES=1
            ;;
        -h|--help)
            cat <<'EOF'
Usage: ./setup.sh [-y|--yes]

  -y, --yes   Answer yes to privileged steps (package installs, setcap)
              without prompting. For scripted/unattended use.
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            echo "Usage: ./setup.sh [-y|--yes]" >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: don't run setup.sh with sudo/as root." >&2
    echo "It creates ./.venv, which must be owned by your normal user account" >&2
    echo "so you can use it afterwards. The script escalates with sudo itself" >&2
    echo "only for the specific steps that need it (package installs, setcap)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# confirm / run_priv — the gateway for every privileged (sudo) action
# ---------------------------------------------------------------------------
confirm() {
    local prompt="$1"
    if [ "$ASSUME_YES" -eq 1 ]; then
        return 0
    fi
    if [ ! -t 0 ]; then
        return 1
    fi
    local answer
    read -rp "$prompt [y/N] " answer || return 1
    case "$(echo "$answer" | tr '[:upper:]' '[:lower:]')" in
        y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

# run_priv <description> <cmd...>
# Prints the description and the exact command, prompts (unless -y), then
# runs it with sudo (if not already root). Returns the command's exit code,
# or 1 if declined/unavailable.
run_priv() {
    local description="$1"
    shift
    local cmd_str="$*"
    local prefix=""
    if [ "$(id -u)" -ne 0 ]; then
        if ! command -v sudo >/dev/null 2>&1; then
            warn "$description requires root, and sudo isn't available."
            echo "  Run as root manually: $cmd_str"
            return 1
        fi
        prefix="sudo "
    fi

    say "$description"
    echo "  Would run: ${prefix}${cmd_str}"
    if ! confirm "Proceed?"; then
        echo "  Skipped. Run manually: ${prefix}${cmd_str}"
        return 1
    fi

    if [ -n "$prefix" ]; then
        sudo "$@"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
detect_os() {
    case "$(uname -s)" in
        Linux) OS_KIND="linux" ;;
        Darwin) OS_KIND="macos" ;;
        *)
            warn "unsupported OS ($(uname -s)) — continuing best-effort, but"
            warn "package-manager steps (nmap install, capabilities) will be skipped."
            OS_KIND="other"
            ;;
    esac
}

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MGR="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MGR="pacman"
    elif [ "$OS_KIND" = "macos" ] && command -v brew >/dev/null 2>&1; then
        PKG_MGR="brew"
    else
        PKG_MGR="none"
        warn "no supported package manager found (apt/dnf/pacman/brew)."
        warn "Package-manager steps below will print manual commands instead."
    fi
}

detect_python() {
    if command -v python3 >/dev/null 2>&1; then
        SYS_PYTHON="python3"
    elif command -v python >/dev/null 2>&1; then
        SYS_PYTHON="python"
    else
        echo "ERROR: no python3/python found on PATH." >&2
        case "$PKG_MGR" in
            apt) echo "  Install it with: sudo apt-get install -y python3" >&2 ;;
            dnf) echo "  Install it with: sudo dnf install -y python3" >&2 ;;
            pacman) echo "  Install it with: sudo pacman -S python" >&2 ;;
            brew) echo "  Install it with: brew install python3" >&2 ;;
            *) echo "  Install Python 3.11+ using your distro's package manager." >&2 ;;
        esac
        exit 1
    fi

    PY_MM="$("$SYS_PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    say "Found $SYS_PYTHON (Python $PY_MM)"

    local major minor
    major="$(echo "$PY_MM" | cut -d. -f1)"
    minor="$(echo "$PY_MM" | cut -d. -f2)"
    if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 11 ]; }; then
        warn "NetScan expects Python 3.11+; found $PY_MM. Things may not work."
    fi
}

# ---------------------------------------------------------------------------
# Step 1: virtual environment
# ---------------------------------------------------------------------------
ensure_venv() {
    if [ -x "$VENV_PY" ] && "$VENV_PY" -c 'import sys' >/dev/null 2>&1; then
        say "Existing virtual environment found at .venv — reusing it."
        STATUS_VENV="ok"
        return 0
    fi

    if [ -d "$VENV_DIR" ]; then
        warn ".venv exists but its interpreter is missing/broken — recreating it."
        rm -rf "$VENV_DIR"
    fi

    if ! "$SYS_PYTHON" -c 'import ensurepip' >/dev/null 2>&1; then
        warn "$SYS_PYTHON is missing the 'ensurepip' module, needed to create a venv."
        case "$PKG_MGR" in
            apt)
                run_priv "Installing python${PY_MM}-venv" \
                    apt-get install -y "python${PY_MM}-venv" || {
                    echo "  If that package name doesn't exist, try: sudo apt-get install -y python3-venv" >&2
                }
                ;;
            dnf)
                echo "  Try: sudo dnf install -y python3" >&2
                ;;
            pacman)
                echo "  Try: sudo pacman -S python" >&2
                ;;
            *)
                echo "  Install your distro's python3-venv (or equivalent) package." >&2
                ;;
        esac
        if ! "$SYS_PYTHON" -c 'import ensurepip' >/dev/null 2>&1; then
            warn "ensurepip is still unavailable — cannot create a virtual environment."
            STATUS_VENV="failed"
            return 1
        fi
    fi

    say "Creating virtual environment at .venv ..."
    if ! "$SYS_PYTHON" -m venv "$VENV_DIR"; then
        warn "venv creation failed."
        rm -rf "$VENV_DIR"
        STATUS_VENV="failed"
        return 1
    fi
    STATUS_VENV="ok"
    return 0
}

# ---------------------------------------------------------------------------
# Step 2: Python dependencies (into the venv)
# ---------------------------------------------------------------------------
install_python_deps() {
    if [ "$STATUS_VENV" != "ok" ]; then
        say "Skipping dependency install — no usable virtual environment."
        STATUS_DEPS="skipped"
        return 1
    fi

    say "Upgrading pip in .venv ..."
    "$VENV_PY" -m pip install --upgrade pip || warn "pip upgrade failed; continuing with existing pip."

    say "Installing Python dependencies into .venv ..."
    if ! "$VENV_PY" -m pip install -r "$SCRIPT_DIR/requirements.txt"; then
        warn "pip install failed."
        STATUS_DEPS="failed"
        return 1
    fi

    if "$VENV_PY" -c "import flask, yaml, requests, nmap" >/dev/null 2>&1; then
        say "Core dependencies (flask, yaml, requests, python-nmap) import cleanly."
        STATUS_DEPS="ok"
        return 0
    else
        warn "one or more core dependencies failed to import after install — see above."
        STATUS_DEPS="failed"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Step 3: nmap binary (the system program, not the Python wrapper)
# ---------------------------------------------------------------------------
ensure_nmap_binary() {
    if command -v nmap >/dev/null 2>&1; then
        say "nmap found: $(command -v nmap) ($(nmap --version | head -1))"
        STATUS_NMAP="ok"
        return 0
    fi

    say "nmap is not installed. This is optional: NetScan falls back to a"
    say "pure-Python scanner without it, with limited fingerprinting and no"
    say "CPE-based CVE correlation."

    case "$PKG_MGR" in
        apt) run_priv "Installing nmap" apt-get install -y nmap ;;
        dnf) run_priv "Installing nmap" dnf install -y nmap ;;
        pacman) run_priv "Installing nmap" pacman -S --noconfirm nmap ;;
        brew) run_priv "Installing nmap" brew install nmap ;;
        *)
            echo "  Install nmap manually, e.g.:" >&2
            echo "    sudo apt install nmap   (Debian/Ubuntu)" >&2
            echo "    sudo dnf install nmap   (RHEL/Fedora)" >&2
            echo "    sudo pacman -S nmap     (Arch)" >&2
            echo "    brew install nmap       (macOS)" >&2
            STATUS_NMAP="skipped"
            return 1
            ;;
    esac

    if command -v nmap >/dev/null 2>&1; then
        say "nmap installed: $(command -v nmap)"
        STATUS_NMAP="ok"
        return 0
    fi
    STATUS_NMAP="skipped"
    return 1
}

# ---------------------------------------------------------------------------
# Step 4: nmap capabilities (Linux only) — lets scans run accurately
# without sudo/root
# ---------------------------------------------------------------------------
grant_nmap_caps() {
    if [ "$OS_KIND" = "macos" ]; then
        say "macOS has no Linux-capabilities mechanism — use 'sudo ./run.sh' for"
        say "SYN scan/OS detection there."
        STATUS_CAPS="skipped"
        return 1
    fi

    if [ "$STATUS_NMAP" != "ok" ]; then
        STATUS_CAPS="skipped"
        return 1
    fi

    local nmap_path
    nmap_path="$(command -v nmap)"
    nmap_path="$(readlink -f "$nmap_path" 2>/dev/null || echo "$nmap_path")"

    if command -v getcap >/dev/null 2>&1; then
        if getcap "$nmap_path" 2>/dev/null | grep -q "cap_net_raw" && \
           getcap "$nmap_path" 2>/dev/null | grep -q "cap_net_admin"; then
            say "nmap already has the capabilities it needs — no sudo required for scans."
            STATUS_CAPS="ok"
            return 0
        fi
    else
        case "$PKG_MGR" in
            apt) run_priv "Installing libcap2-bin (provides setcap/getcap)" apt-get install -y libcap2-bin ;;
            dnf) run_priv "Installing libcap (provides setcap/getcap)" dnf install -y libcap ;;
            pacman) run_priv "Installing libcap (provides setcap/getcap)" pacman -S --noconfirm libcap ;;
        esac
    fi

    if ! command -v setcap >/dev/null 2>&1; then
        warn "setcap is not available — cannot grant nmap capabilities."
        STATUS_CAPS="skipped"
        return 1
    fi

    say "Granting nmap raw-socket capabilities lets scans use SYN scan +"
    say "service/version detection WITHOUT sudo. Note this does NOT cover OS"
    say "detection (-O) -- nmap hard-requires actual root for that regardless"
    say "of capabilities, so 'sudo ./run.sh' is still needed for OS"
    say "fingerprinting specifically. Also note: granting this lets any local"
    say "user on this machine run raw-socket scans with nmap -- fine on a"
    say "single-user box, worth knowing on a shared one."

    if run_priv "Setting capabilities on nmap" setcap cap_net_raw,cap_net_admin+eip "$nmap_path"; then
        STATUS_CAPS="ok"
        return 0
    fi
    STATUS_CAPS="skipped"
    return 1
}

# ---------------------------------------------------------------------------
# Step 5: config.yaml
# ---------------------------------------------------------------------------
ensure_config() {
    if [ -f "$SCRIPT_DIR/config.yaml" ]; then
        say "config.yaml already exists."
        STATUS_CONFIG="ok"
        return 0
    fi
    if [ ! -f "$SCRIPT_DIR/config.example.yaml" ]; then
        warn "neither config.yaml nor config.example.yaml found."
        STATUS_CONFIG="failed"
        return 1
    fi
    say "config.yaml not found. Copying from config.example.yaml..."
    cp "$SCRIPT_DIR/config.example.yaml" "$SCRIPT_DIR/config.yaml"
    say "A default config.yaml was created. Edit it to set your real"
    say "network targets before scanning."
    STATUS_CONFIG="ok"
    return 0
}

# ---------------------------------------------------------------------------
# Step 6: desktop launcher (Linux only -- avoids the class of mistake where
# someone navigates to a stale/wrong copy of this folder by hand instead of
# using a fixed shortcut)
# ---------------------------------------------------------------------------
create_desktop_launcher() {
    if [ "$OS_KIND" != "linux" ]; then
        STATUS_DESKTOP="skipped"
        return 1
    fi

    local desktop_dir=""
    if command -v xdg-user-dir >/dev/null 2>&1; then
        local candidate
        candidate="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
        if [ -n "$candidate" ] && [ "$candidate" != "$HOME" ] && [ -d "$candidate" ]; then
            desktop_dir="$candidate"
        fi
    fi
    if [ -z "$desktop_dir" ] && [ -d "$HOME/Desktop" ]; then
        desktop_dir="$HOME/Desktop"
    fi
    if [ -z "$desktop_dir" ]; then
        # No GUI desktop (headless box) -- nothing to do, nothing to warn about.
        STATUS_DESKTOP="skipped"
        return 1
    fi

    local run_launcher="$desktop_dir/NetScan.desktop"
    local setup_launcher="$desktop_dir/NetScan Setup.desktop"

    cat > "$run_launcher" <<EOF
[Desktop Entry]
Type=Application
Name=NetScan
Comment=Launch NetScan network scanner (asks for your password so scans include OS detection)
Exec=sudo "$SCRIPT_DIR/run.sh"
Path=$SCRIPT_DIR
Terminal=true
Icon=utilities-terminal
Categories=Network;Security;
EOF

    cat > "$setup_launcher" <<EOF
[Desktop Entry]
Type=Application
Name=NetScan Setup
Comment=Re-run NetScan's first-time setup (fix dependencies, nmap, capabilities)
Exec="$SCRIPT_DIR/setup.sh"
Path=$SCRIPT_DIR
Terminal=true
Icon=utilities-terminal
Categories=Network;Security;
EOF

    if chmod +x "$run_launcher" "$setup_launcher" 2>/dev/null; then
        say "Desktop shortcuts created: 'NetScan' and 'NetScan Setup' in $desktop_dir"
        say "If double-clicking does nothing at first, right-click the icon and"
        say "choose 'Allow Launching' (GNOME marks new launchers untrusted)."
        STATUS_DESKTOP="ok"
        return 0
    fi
    warn "failed to create desktop launcher(s) in $desktop_dir"
    STATUS_DESKTOP="failed"
    return 1
}

# ---------------------------------------------------------------------------
# Step 7: smoke test
# ---------------------------------------------------------------------------
smoke_test() {
    if [ "$STATUS_DEPS" != "ok" ]; then
        STATUS_SMOKE="skipped"
        return 1
    fi
    say "Running smoke test (python run.py profiles) ..."
    if "$VENV_PY" "$SCRIPT_DIR/run.py" profiles >/tmp/netscan_setup_smoke.$$ 2>&1; then
        say "Smoke test passed."
        STATUS_SMOKE="ok"
        rm -f "/tmp/netscan_setup_smoke.$$"
        return 0
    else
        warn "Smoke test failed — this suggests a broken source tree, not a"
        warn "missing dependency (those were already verified above):"
        cat "/tmp/netscan_setup_smoke.$$" >&2
        rm -f "/tmp/netscan_setup_smoke.$$"
        STATUS_SMOKE="failed"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
detect_os
detect_pkg_manager
detect_python

ensure_venv
install_python_deps
ensure_nmap_binary
grant_nmap_caps
ensure_config
create_desktop_launcher
smoke_test

echo
echo "============================================"
echo "  Setup summary"
echo "============================================"
printf "  %-28s %s\n" "Virtual environment (.venv):" "$STATUS_VENV"
printf "  %-28s %s\n" "Python dependencies:" "$STATUS_DEPS"
printf "  %-28s %s\n" "nmap binary:" "$STATUS_NMAP"
printf "  %-28s %s\n" "nmap capabilities:" "$STATUS_CAPS"
printf "  %-28s %s\n" "config.yaml:" "$STATUS_CONFIG"
printf "  %-28s %s\n" "Desktop launcher:" "$STATUS_DESKTOP"
printf "  %-28s %s\n" "Smoke test:" "$STATUS_SMOKE"
echo

if [ "$STATUS_VENV" != "ok" ] || [ "$STATUS_DEPS" != "ok" ]; then
    echo "Setup did not complete successfully — see warnings above." >&2
    exit 1
fi

echo "Next steps:"
echo "  1. Edit config.yaml — set 'targets:' to what you're authorized to scan."
echo "  2. Run: ./run.sh   (it auto-detects and uses .venv)"
echo
if [ "$STATUS_CAPS" = "ok" ]; then
    echo "  nmap has the capabilities it needs — plain './run.sh' (no sudo) now"
    echo "  gets full SYN scan + service/version detection accuracy."
    echo "  OS detection (-O) still needs 'sudo ./run.sh' -- nmap hard-requires"
    echo "  real root for that specifically, regardless of capabilities. Without"
    echo "  it, OS fingerprinting is skipped (with a warning) but the rest of"
    echo "  the scan still completes normally."
else
    echo "  For SYN scan + service detection accuracy without sudo, re-run this"
    echo "  script and accept the capability-granting step. OS detection (-O)"
    echo "  needs 'sudo ./run.sh' regardless -- capabilities can't provide it."
    echo
    echo "  If you run manual commands with sudo yourself, note that sudo resets"
    echo "  PATH by default, so an activated venv is silently ignored and you'll"
    echo "  get confusing 'module not found' errors from the system Python."
    echo "  Use the venv interpreter by absolute path instead:"
    echo "    sudo ./.venv/bin/python run.py scan -c config.yaml"
    echo "  ./run.sh itself is immune to this — it invokes .venv/bin/python by"
    echo "  absolute path, so 'sudo ./run.sh' works correctly."
fi
echo
echo "  3. Open http://127.0.0.1:8000 after choosing option 3 in ./run.sh."

exit 0
