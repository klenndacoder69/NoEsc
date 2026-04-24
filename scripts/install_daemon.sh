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
# Kill any currently running old versions of the daemon
pkill noesc_daemon || true

cp noesc_daemon /usr/local/bin/
chmod +x /usr/local/bin/noesc_daemon

echo "[*] Step 2b: Installing maintenance helper command..."
cp scripts/noesc-maint.sh /usr/local/bin/noesc-maint
chmod +x /usr/local/bin/noesc-maint

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

echo "[*] Step 6: Restarting Auditd Service..."
# systemd often refuses to restart auditd directly due to security constraints.
# Sending a SIGHUP signal forces auditd to re-read its configuration and respawn plugins safely.
pkill -HUP auditd || kill -s SIGHUP $(pidof auditd)

echo "----------------------------------------------------"
echo "[+] INSTALLATION COMPLETE!"
echo "    - The daemon is now running silently in the background."
echo "    - Switch engine mode:  sudo noesc-engine hybrid|ml-only|rules-only"
echo "    - Check engine mode:   sudo noesc-engine status"
echo "    - Start ML service:    sudo systemctl enable --now noesc-ml-listener"
echo "    - Check ML service:    sudo systemctl status noesc-ml-listener"
echo "    - To edit whitelist:  nano /etc/noesc/suid_whitelist.conf"
echo "    - ML env file:        nano /etc/noesc/ml_listener.env"
echo "    - Project .env file:  nano $PROJECT_ROOT/.env"
echo "    - Maintenance mode:   noesc-maint status|on 30m|off"
echo "    - To view alerts:     cat /var/log/noesc_alerts.log"
echo "----------------------------------------------------"
