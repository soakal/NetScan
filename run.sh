#!/usr/bin/env bash
# NetScan launcher for Linux/macOS — the run.bat equivalent.
set -uo pipefail
cd "$(dirname "$0")"

PYTHON=python3
command -v python3 >/dev/null 2>&1 || PYTHON=python

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
    # This file may later contain API keys/passwords; never create it
    # group/world-readable under a permissive user umask.
    (umask 077 && cp config.example.yaml config.yaml)
    echo "A default config.yaml was created. Edit it to set your real"
    echo "network targets before scanning, then re-run this option."
    return 1
}

pause() {
    read -rp "Press Enter to continue..." _ || true
}

sudo_hint() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Note: not running as root — nmap SYN scan/OS detection is more"
        echo "accurate with elevated privileges for the *scan* only."
        echo "Prefer: sudo \"$PYTHON\" run.py scan -c config.yaml"
        echo "then serve as your normal user (option 2). Continuing without it."
        echo
    fi
}

# Run the report server without root when possible (scan may need sudo; serve should not).
serve_report() {
    echo
    echo "Starting report server at http://127.0.0.1:8000"
    echo "Press Ctrl+C to stop."
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        echo "Dropping privileges to ${SUDO_USER} for the report server."
        sudo -u "$SUDO_USER" -- "$PYTHON" run.py serve -c config.yaml
    else
        if [ "$(id -u)" -eq 0 ]; then
            echo "WARNING: report server is running as root. Prefer serving as a normal user."
        fi
        "$PYTHON" run.py serve -c config.yaml
    fi
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
            serve_report
            ;;
        3)
            check_config || { pause; continue; }
            sudo_hint
            echo "Running scan..."
            if ! "$PYTHON" run.py scan -c config.yaml; then
                echo
                echo "Scan failed. Not starting the report server."
                pause
                continue
            fi
            serve_report
            ;;
        4)
            echo
            echo "Seeding demo data..."
            if ! "$PYTHON" run.py demo; then
                echo "Demo seed failed. Not starting the report server."
                pause
                continue
            fi
            echo "Starting report server at http://127.0.0.1:8000"
            echo "Press Ctrl+C to stop."
            if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
                sudo -u "$SUDO_USER" -- "$PYTHON" run.py serve
            else
                "$PYTHON" run.py serve
            fi
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
