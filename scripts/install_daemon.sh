#!/bin/bash

# NoEsc Daemon Installation Script
# This script compiles the C++ program and installs it as a background audispd plugin.

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./scripts/install_daemon.sh)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Installed paths (must match steps below)
NOESC_DAEMON_BIN="/usr/local/bin/noesc_daemon"
NOESC_WRAPPER_BIN="/usr/local/bin/noesc-daemon-wrapper"

wait_for_noesc_daemon() {
    local timeout_secs="${1:-45}"
    local deadline=$(( $(date +%s) + timeout_secs ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if pgrep -f "^${NOESC_DAEMON_BIN}($| )" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

restart_auditd_for_plugin() {
    pkill -f "^${NOESC_DAEMON_BIN}($| )" >/dev/null 2>&1 || true
    pkill -f "noesc-daemon-wrapper" >/dev/null 2>&1 || true
    sleep 0.5

    if command -v systemctl >/dev/null 2>&1; then
        if systemctl restart auditd >/dev/null 2>&1; then
            echo "[+] auditd restarted (plugin should spawn immediately)"
            return 0
        fi
    fi
    if pgrep -x auditd >/dev/null 2>&1; then
        pkill -HUP auditd || kill -s SIGHUP "$(pidof auditd)" || true
        echo "[+] auditd signaled (HUP) — plugin respawning"
        return 0
    fi
    echo "[!] auditd is not running; cannot attach plugin."
    return 1
}

# Skip all apt network work (offline / air-gapped): sudo NOESC_SKIP_APT=1 ./scripts/install_daemon.sh
# When deps are already installed, apt is skipped automatically (fast reinstall).

apt_deps_already_satisfied() {
    command -v g++ >/dev/null 2>&1 || return 1
    command -v make >/dev/null 2>&1 || return 1
    command -v auditd >/dev/null 2>&1 || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -m venv -h >/dev/null 2>&1 || return 1
    command -v notify-send >/dev/null 2>&1 || return 1
    command -v rg >/dev/null 2>&1 || return 1
    dpkg -s audispd-plugins >/dev/null 2>&1 || return 1
    return 0
}

run_apt_install() {
    export DEBIAN_FRONTEND=noninteractive
    # Fail faster when there is no network or mirrors are slow.
    local apt_opts=(
        -o Acquire::Retries=2
        -o Acquire::http::Timeout=15
        -o Acquire::https::Timeout=15
    )
    apt-get "${apt_opts[@]}" update -qq || true
    apt-get "${apt_opts[@]}" install -yq --no-install-recommends \
        g++ make auditd audispd-plugins python3 python3-venv python3-pip \
        libnotify-bin dbus-user-session ripgrep
}

echo "[*] Step 0: Installing and verifying system dependencies..."
if [ "${NOESC_SKIP_APT:-0}" = "1" ]; then
    echo "    NOESC_SKIP_APT=1 — skipping apt-get (ensure deps are installed manually)."
    if ! apt_deps_already_satisfied; then
        echo "[!] Required commands/packages appear missing. Install g++, make, auditd, audispd-plugins, python3+venv, libnotify-bin, ripgrep, etc., then retry."
        INSTALL_FAILED=1
    fi
elif command -v apt-get >/dev/null 2>&1; then
    if apt_deps_already_satisfied; then
        echo "    Detected apt-based system. Dependencies already present; skipping apt-get update/install."
    else
        echo "    Detected apt-based system. Attempting automatic dependency installation..."
        if ! run_apt_install; then
            echo "[!] Warning: Automatic installation via apt-get failed."
            INSTALL_FAILED=1
        fi
    fi
else
    echo "[!] Warning: 'apt-get' not found. Automatic dependency installation is only supported on Debian/Ubuntu."
    INSTALL_FAILED=1
fi

if [ "${INSTALL_FAILED:-0}" -eq 1 ]; then
    echo "----------------------------------------------------------------------"
    echo "Refer to README.md and ensure the following system dependencies are installed: "
    echo "  - C++ Compiler and Make (g++, make)"
    echo "  - Audit daemon and plugins (auditd, audispd-plugins)"
    echo "  - Python 3 and venv (python3, python3-venv, python3-pip)"
    echo "  - Desktop notification tools (libnotify-bin, dbus-x11)"
    echo "----------------------------------------------------------------------"
    read -p "Press [Enter] to continue if you have already installed these, or Ctrl+C to abort..."
fi

echo "[*] Step 0.5: Setting up Python ML environment..."
if [ ! -d ".venv" ]; then
    echo "    Creating virtual environment at .venv..."
    if ! python3 -m venv .venv; then
        echo "[-] Failed to create Python virtual environment. Please install python3-venv manually."
        exit 1
    fi
fi
echo "    Installing Python requirements..."
# We explicitly use the venv pip so we don't pollute the system python
if ! .venv/bin/pip install -q -r requirements.txt; then
    echo "[-] Failed to automatically install Python requirements."
    echo "    Please run: source .venv/bin/activate && pip install -r requirements.txt manually."
    exit 1
fi

echo "[*] Step 1: Compiling NoEsc Daemon..."
make clean > /dev/null
make
if [ ! -f "noesc_daemon" ]; then
    echo "[-] Compilation failed! Please check for errors."
    exit 1
fi

echo "[*] Step 2: Installing binary to /usr/local/bin..."
# Use atomic rename to avoid "Text file busy" errors.
# cp to a temp path first, then mv (rename syscall) atomically replaces
# the directory entry even if the old binary is still being executed.
cp noesc_daemon /usr/local/bin/noesc_daemon.new
chmod +x /usr/local/bin/noesc_daemon.new
mv -f /usr/local/bin/noesc_daemon.new /usr/local/bin/noesc_daemon

echo "[*] Step 2b: Installing maintenance helper command..."
cp scripts/noesc-maint.sh /usr/local/bin/noesc-maint
chmod +x /usr/local/bin/noesc-maint

echo "[*] Step 2b.1: Installing health check helper command..."
cp scripts/noesc-health.sh /usr/local/bin/noesc-health
chmod +x /usr/local/bin/noesc-health

echo "[*] Step 2c: Installing engine wrapper and switch command..."
cp scripts/noesc-daemon-wrapper.sh /usr/local/bin/noesc-daemon-wrapper
chmod +x /usr/local/bin/noesc-daemon-wrapper

cp scripts/noesc-engine.sh /usr/local/bin/noesc-engine
chmod +x /usr/local/bin/noesc-engine

echo "[*] Step 2d: Installing ML listener launcher..."
cp scripts/noesc-ml-listener-launcher.sh /usr/local/bin/noesc-ml-listener-launcher
chmod +x /usr/local/bin/noesc-ml-listener-launcher

echo "[*] Step 3: Installing configuration files..."
mkdir -p /etc/noesc
cp config/suid_whitelist.conf /etc/noesc/
chmod 644 /etc/noesc/suid_whitelist.conf

# ML process whitelist — skip inference on known-safe system daemons.
if [ ! -f /etc/noesc/ml_process_whitelist.conf ]; then
    cp config/ml_process_whitelist.conf /etc/noesc/
fi
chmod 644 /etc/noesc/ml_process_whitelist.conf

# Default deployed engine mode for audisp plugin wrapper.
if [ ! -f /etc/noesc/engine_mode ]; then
    echo "hybrid" > /etc/noesc/engine_mode
fi
chmod 644 /etc/noesc/engine_mode

# Optional: stable GUI username for desktop alerts (see /etc/noesc/notify_user).
if [ ! -f /etc/noesc/notify_user.example ]; then
    cat > /etc/noesc/notify_user.example <<'EOF'
# Optional: put your GUI login name on a single line in /etc/noesc/notify_user
# (not this file). Improves notification reliability after lock/login on Ubuntu/GDM.
# Example line for notify_user:
# swuffles
EOF
    chmod 644 /etc/noesc/notify_user.example
fi

# Seed ML listener environment file once (operator can edit after install).
if [ ! -f /etc/noesc/ml_listener.env ]; then
    DEFAULT_PYTHON_BIN="python3"
    if [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
        DEFAULT_PYTHON_BIN="$PROJECT_ROOT/.venv/bin/python"
    fi

    sed \
      -e "s|__NOESC_PROJECT_ROOT__|$PROJECT_ROOT|g" \
      -e "s|__NOESC_PYTHON_BIN__|$DEFAULT_PYTHON_BIN|g" \
      config/ml_listener.env.example > /etc/noesc/ml_listener.env
fi
chmod 644 /etc/noesc/ml_listener.env

# Seed project-level .env once so launcher can run without relying on /etc edits.
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    DEFAULT_PYTHON_BIN="python3"
    if [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
        DEFAULT_PYTHON_BIN="$PROJECT_ROOT/.venv/bin/python"
    fi

    sed \
      -e "s|__NOESC_PROJECT_ROOT__|$PROJECT_ROOT|g" \
      -e "s|__NOESC_PYTHON_BIN__|$DEFAULT_PYTHON_BIN|g" \
      config/ml_listener.env.example > "$PROJECT_ROOT/.env"
fi
chmod 644 "$PROJECT_ROOT/.env"

echo "[*] Step 4: Initializing Dedicated Alert Log..."
touch /var/log/noesc_alerts.log
# Only root should read security alerts
chmod 600 /var/log/noesc_alerts.log

echo "[*] Step 4.5: Ensuring auditd is running..."
# On a fresh Ubuntu install, auditd is installed but not yet started.
# The plugin directory and rule reload both require auditd to have run at least once.
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable auditd > /dev/null 2>&1 || true
    systemctl start auditd 2>/dev/null || true
    sleep 1
fi
# Ensure the plugins directory exists (created by auditd on first start)
if [ ! -d "/etc/audit/plugins.d" ]; then
    mkdir -p /etc/audit/plugins.d
fi
if [ ! -d "/etc/audit/rules.d" ]; then
    mkdir -p /etc/audit/rules.d
fi

echo "[*] Step 5: Registering Audispd Plugin..."
# If plugins.d doesn't exist, audispd might be using an older format, 
# but modern Ubuntu/Debian uses plugins.d
if [ -d "/etc/audit/plugins.d" ]; then
    cp config/noesc.conf /etc/audit/plugins.d/
    chmod 640 /etc/audit/plugins.d/noesc.conf
else
    echo "[-] /etc/audit/plugins.d not found. Plugin registration failed."
    exit 1
fi

echo "[*] Step 5.5: Injecting Audit Rules..."
if [ -d "/etc/audit/rules.d" ]; then
    cp config/noesc.rules /etc/audit/rules.d/99-noesc.rules
    chmod 640 /etc/audit/rules.d/99-noesc.rules
    if command -v augenrules >/dev/null 2>&1; then
        echo "    Reloading audit rules..."
        augenrules --load > /dev/null 2>&1 || true
    fi
else
    echo "[-] /etc/audit/rules.d not found. Rule injection skipped."
fi

echo "[*] Step 5b: Installing and enabling ML listener systemd unit..."
if command -v systemctl >/dev/null 2>&1; then
    cp config/noesc-ml-listener.service /etc/systemd/system/noesc-ml-listener.service
    chmod 644 /etc/systemd/system/noesc-ml-listener.service
    systemctl daemon-reload
    systemctl enable noesc-ml-listener > /dev/null 2>&1 || true
else
    echo "[!] systemctl not found; skipped ML listener service install"
fi

echo "[*] Step 5c: Protecting ML socket from systemd-tmpfiles-clean..."
# systemd-tmpfiles-clean.timer periodically purges stale files from /tmp.
# Without this exclusion, the ML listener's Unix domain socket gets deleted
# after ~15 min of inactivity, silently breaking the UDS bridge.
echo 'x /tmp/noesc_ml.sock' > /etc/tmpfiles.d/noesc.conf
chmod 644 /etc/tmpfiles.d/noesc.conf

echo "[*] Step 6: Restarting services..."
# Remove stale ML socket so the listener can bind a fresh one.
rm -f /tmp/noesc_ml.sock

# Restart ML listener first (so socket is ready when daemon starts).
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart noesc-ml-listener 2>/dev/null || true
    sleep 1
fi

# Force auditd to respawn the plugin immediately (full restart when possible).
restart_auditd_for_plugin || true

echo "    Waiting for NoEsc daemon process..."
if wait_for_noesc_daemon 45; then
    echo "[+] NoEsc daemon is running:"
    pgrep -af "^${NOESC_DAEMON_BIN}($| )" | head -n3 | sed 's/^/       /'
else
    echo "[!] NoEsc daemon did not appear within 45s."
    echo "    Check: sudo systemctl status auditd --no-pager"
    echo "    Logs:  sudo journalctl -u auditd -n 60 --no-pager"
fi

echo "----------------------------------------------------"
echo "[+] INSTALLATION COMPLETE!"
echo "    - Switch engine mode:  sudo noesc-engine hybrid|ml-only|rules-only"
echo "    - Check engine mode:   sudo noesc-engine status"
echo "    - Start ML service:    sudo systemctl enable --now noesc-ml-listener"
echo "    - Check ML service:    sudo systemctl status noesc-ml-listener"
echo "    - To edit whitelist:  nano /etc/noesc/suid_whitelist.conf"
echo "    - ML env file:        nano /etc/noesc/ml_listener.env"
echo "    - Project .env file:  nano $PROJECT_ROOT/.env"
echo "    - Maintenance mode:   noesc-maint status|on 30m|off"
echo "    - Health check:       noesc-health"
echo "    - To view alerts:     cat /var/log/noesc_alerts.log"
echo "----------------------------------------------------"

