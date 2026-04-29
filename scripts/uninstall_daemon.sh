#!/bin/bash
set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./scripts/uninstall_daemon.sh)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "[*] NoEsc uninstall started..."

remove_file_if_exists() {
  local path="$1"
  if [ -e "$path" ]; then
    rm -f "$path"
    echo "    removed: $path"
  fi
}

echo "[*] Step 1: Stopping and disabling services..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now noesc-ml-listener >/dev/null 2>&1 || true
fi

echo "[*] Step 2: Stopping running NoEsc processes..."
pkill -f "noesc_daemon" >/dev/null 2>&1 || true
pkill -f "model_interface.py" >/dev/null 2>&1 || true

echo "[*] Step 3: Removing installed binaries/wrappers..."
remove_file_if_exists "/usr/local/bin/noesc_daemon"
remove_file_if_exists "/usr/local/bin/noesc-daemon-wrapper"
remove_file_if_exists "/usr/local/bin/noesc-engine"
remove_file_if_exists "/usr/local/bin/noesc-maint"
remove_file_if_exists "/usr/local/bin/noesc-health"
remove_file_if_exists "/usr/local/bin/noesc-ml-listener-launcher"

echo "[*] Step 4: Removing auditd plugin and rules..."
remove_file_if_exists "/etc/audit/plugins.d/noesc.conf"
remove_file_if_exists "/etc/audisp/plugins.d/noesc.conf"
remove_file_if_exists "/etc/audit/rules.d/99-noesc.rules"

if command -v augenrules >/dev/null 2>&1; then
  augenrules --load >/dev/null 2>&1 || true
fi

echo "[*] Step 5: Removing systemd unit and tmpfiles override..."
remove_file_if_exists "/etc/systemd/system/noesc-ml-listener.service"
remove_file_if_exists "/etc/tmpfiles.d/noesc.conf"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

echo "[*] Step 6: Removing runtime/config artifacts..."
remove_file_if_exists "/tmp/noesc_ml.sock"
remove_file_if_exists "/var/log/noesc_alerts.log"

if [ -d "/etc/noesc" ]; then
  rm -rf "/etc/noesc"
  echo "    removed: /etc/noesc"
fi

# Keep project's local .env by default to avoid deleting operator customizations.
# Admin can remove it manually if they want a pristine repo working tree.
if [ -f "$PROJECT_ROOT/.env" ]; then
  echo "    kept: $PROJECT_ROOT/.env (project-local file)"
fi

echo "[*] Step 7: Reloading auditd to drop NoEsc plugin..."
if pgrep -x auditd >/dev/null 2>&1; then
  pkill -HUP auditd >/dev/null 2>&1 || kill -s SIGHUP "$(pidof auditd)" || true
  echo "    auditd reloaded"
else
  echo "    auditd not running; reload skipped"
fi

echo "[+] NoEsc uninstall complete."
