#!/bin/bash

# NoEsc Daemon Installation Script
# This script compiles the C++ program and installs it as a background audispd plugin.

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./scripts/install_daemon.sh)"
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
# Kill any currently running old versions of the daemon
pkill noesc_daemon || true

cp noesc_daemon /usr/local/bin/
chmod +x /usr/local/bin/noesc_daemon

echo "[*] Step 3: Installing configuration files..."
mkdir -p /etc/noesc
cp config/suid_whitelist.conf /etc/noesc/
chmod 644 /etc/noesc/suid_whitelist.conf

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

echo "[*] Step 6: Restarting Auditd Service..."
# systemd often refuses to restart auditd directly due to security constraints.
# Sending a SIGHUP signal forces auditd to re-read its configuration and respawn plugins safely.
pkill -HUP auditd || kill -s SIGHUP $(pidof auditd)

echo "----------------------------------------------------"
echo "[+] INSTALLATION COMPLETE!"
echo "    - The daemon is now running silently in the background."
echo "    - To edit whitelist:  nano /etc/noesc/suid_whitelist.conf"
echo "    - To view alerts:     cat /var/log/noesc_alerts.log"
echo "----------------------------------------------------"
