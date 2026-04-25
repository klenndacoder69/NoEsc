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

echo "[*] Step 5b: Installing ML listener systemd unit..."
if command -v systemctl >/dev/null 2>&1; then
    cp config/noesc-ml-listener.service /etc/systemd/system/noesc-ml-listener.service
    chmod 644 /etc/systemd/system/noesc-ml-listener.service
    systemctl daemon-reload
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
# Kill old daemon so auditd respawns it with the new binary.
pkill -f "noesc_daemon" >/dev/null 2>&1 || true
sleep 1

# Remove stale ML socket so the listener can bind a fresh one.
rm -f /tmp/noesc_ml.sock

# Restart ML listener first (so socket is ready when daemon starts).
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart noesc-ml-listener 2>/dev/null || true
    sleep 2
fi

# Reload auditd — this respawns the daemon plugin with the new binary.
if pgrep -x auditd >/dev/null 2>&1; then
    pkill -HUP auditd || kill -s SIGHUP "$(pidof auditd)"
    echo "[+] auditd reloaded — daemon plugin respawning"
else
    echo "[!] auditd is not running"
fi

# Give auditd a moment to respawn the plugin.
sleep 2

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

