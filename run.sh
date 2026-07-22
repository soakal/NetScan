#!/usr/bin/env bash
# NetScan launcher for Linux/macOS — the run.bat equivalent.
set -uo pipefail
cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"

# Running from a Trash/Recycle-bin copy is never intentional -- it happens
# when a file manager auto-renames-and-trashes a same-named folder during a
# drag/drop replace, and someone then unknowingly opens a terminal inside
# the trashed copy. That copy is stale by definition, so hard-refuse rather
# than warn (a warning here has already been missed once).
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

# Running the whole app as root (via sudo) just to let nmap open raw sockets
# leaves every file it writes (netscan.db, .netscan_cache/, __pycache__/)
# root-owned -- which then can't be deleted/edited by the normal user without
# sudo again. Guard against that by handing ownership back on exit. NOTE:
# sudo is NOT refused just because nmap already has capabilities -- those
# only cover SYN scan/service detection, not OS detection (-O), which nmap
# hard-requires real root for regardless of capabilities. So sudo remains
# useful (for -O) even on a fully-capable box.
if [ "$(id -u)" -eq 0 ]; then
    if [ -z "${SUDO_USER:-}" ]; then
        # Genuinely running as root with no invoking user to hand files back
        # to (containers, root-only appliances) -- root-owned files here are
        # correct, not a mistake. Just note it and continue.
        echo "Note: running as root directly (no sudo/SUDO_USER) -- files"
        echo "created this session will be root-owned."
        echo
    else
        # sudo: proceed, but avoid/undo root ownership of anything this
        # session creates.
        OWNER_UID="$SUDO_UID"
        OWNER_GID="$SUDO_GID"
        export PYTHONDONTWRITEBYTECODE=1
        trap 'chown -R "$OWNER_UID:$OWNER_GID" "$SCRIPT_DIR" 2>/dev/null' EXIT
        echo "Running as root via sudo -- files created this session will be handed"
        echo "back to $SUDO_USER on exit."
        echo
    fi
fi

if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON="$SCRIPT_DIR/.venv/bin/python"
else
    PYTHON=python3
    command -v python3 >/dev/null 2>&1 || PYTHON=python
    if ! "$PYTHON" -c 'import flask, yaml' >/dev/null 2>&1; then
        echo "Dependencies aren't installed yet — run ./setup.sh first"
        echo "(recommended; installs everything into a local .venv)."
        echo
    fi
fi

check_config() {
    if [ -f config.yaml ]; then
        return 0
    fi
    if [ ! -f config.example.yaml ]; then
        echo
        echo "ERROR: Neither config.yaml nor config.example.yaml was found."
        echo "Restore config.example.yaml or re-download the app, then try again."
        return 1
    fi
    echo
    echo "config.yaml not found. Copying from config.example.yaml..."
    cp config.example.yaml config.yaml
    echo "A default config.yaml was created. Edit it to set your real"
    echo "network targets before scanning, then re-run this option."
    return 1
}

pause() {
    read -rp "Press Enter to continue..." _ || true
}

sudo_hint() {
    if [ "$(id -u)" -eq 0 ]; then
        return
    fi
    if command -v getcap >/dev/null 2>&1 && command -v nmap >/dev/null 2>&1; then
        local nmap_path
        nmap_path="$(readlink -f "$(command -v nmap)" 2>/dev/null || command -v nmap)"
        if getcap "$nmap_path" 2>/dev/null | grep -q "cap_net_raw"; then
            echo "Note: nmap has raw-socket capabilities — SYN scan/service"
            echo "detection are fully accurate without sudo. OS detection"
            echo "specifically still needs 'sudo ./run.sh' (nmap hard-requires"
            echo "real root for that, regardless of capabilities); without it,"
            echo "OS fingerprinting is skipped but the rest of the scan runs fine."
            echo
            return
        fi
    fi
    echo "Note: nmap SYN scan/OS detection is less accurate without raw-socket access."
    echo "Recommended (one-time): ./setup.sh grants nmap the capability for SYN"
    echo "scan/service detection without sudo (OS detection will still need"
    echo "'sudo ./run.sh' either way). Or just use 'sudo ./run.sh' now — the"
    echo "launcher will hand file ownership back to you on exit."
    echo
}

while true; do
    clear
    cat <<'EOF'
============================================
  NetScan
============================================

  1. Scan your network
  2. Serve the report (http://127.0.0.1:8000)
  3. Scan, then serve the report
  4. Demo mode (no network needed, sample data)
  5. List scan profiles
  0. Exit

EOF
    if ! read -rp "Choose an option: " choice; then
        echo
        break
    fi

    case "$choice" in
        1)
            check_config || { pause; continue; }
            sudo_hint
            echo "Running scan..."
            "$PYTHON" run.py scan -c config.yaml
            echo
            pause
            ;;
        2)
            check_config || { pause; continue; }
            echo
            echo "Starting report server at http://127.0.0.1:8000"
            echo "Press Ctrl+C to stop."
            "$PYTHON" run.py serve -c config.yaml
            ;;
        3)
            check_config || { pause; continue; }
            sudo_hint
            echo "Running scan..."
            "$PYTHON" run.py scan -c config.yaml
            echo
            echo "Starting report server at http://127.0.0.1:8000"
            echo "Press Ctrl+C to stop."
            "$PYTHON" run.py serve -c config.yaml
            ;;
        4)
            echo
            echo "Seeding demo data..."
            "$PYTHON" run.py demo
            echo "Starting report server at http://127.0.0.1:8000"
            echo "Press Ctrl+C to stop."
            "$PYTHON" run.py serve
            ;;
        5)
            echo
            "$PYTHON" run.py profiles
            echo
            pause
            ;;
        0)
            break
            ;;
        *)
            echo "Invalid choice."
            pause
            ;;
    esac
done
