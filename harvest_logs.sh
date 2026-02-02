#!/bin/bash

# NoEsc - Benign Data Harvesting Deployment Script
# Author: Klenn Jakek Borja
# Target: Ubuntu/Debian based Linux Systems (ICS Lab)

# 1. CHECK FOR ROOT
if [ "$EUID" -ne 0 ]; then 
  echo "[-] Please run as root (sudo ./deploy_harvest.sh)"
  exit
fi

echo "[*] Starting NoEsc Harvest Setup..."

# 2. BACKUP CONFIGURATIONS (Safety Net)
echo "[*] Backing up existing audit configurations..."
cp /etc/audit/auditd.conf /etc/audit/auditd.conf.bak_noesc
cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.bak_noesc

# 3. CONFIGURE LOG ROTATION & DISK SAFETY
# We modify auditd.conf to ensure the disk never fills up.
# This makes it safe to leave running for weeks.
echo "[*] Configuring Log Rotation (Safety limits)..."

# Set max log file size to 20MB
sed -i 's/^max_log_file =.*/max_log_file = 20/' /etc/audit/auditd.conf
# Keep only 5 rotated logs (Max 100MB total usage)
sed -i 's/^num_logs =.*/num_logs = 5/' /etc/audit/auditd.conf
# When full, ROTATE (delete oldest), don't suspend system
sed -i 's/^max_log_file_action =.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
# Ensure we define the space_left_action to ignore (prevents syslog spam if low disk)
sed -i 's/^space_left_action =.*/space_left_action = IGNORE/' /etc/audit/auditd.conf

# 4. INJECT HARVESTING RULES
# We create a new rule file. These persist across reboots.
echo "[*] Injecting Data Collection Rules..."

cat > /etc/audit/rules.d/99-noesc-harvest.rules <<EOF
## NoEsc Harvesting Rules
## CLEARS ALL EXISTING RULES FIRST
-D

## Buffer size (prevent event loss on busy systems)
-b 8192

## Failure Mode (0=silent, 1=printk, 2=panic). Set to 1 for safety.
-f 1

## --- RULESET ---

## 1. IGNORE SYSTEM NOISE
## We don't care about cron jobs or system services.
## We only want Human (Student) Activity.
## auid>=1000 targets created users. auid!=-1 removes unset users.

## 2. CAPTURE COMMAND EXECUTION (For N-Gram/ML)
## This captures every command a student types or script they run.
-a always,exit -F arch=b64 -S execve,execveat -F auid>=1000 -F auid!=-1 -k benign_exec
-a always,exit -F arch=b32 -S execve,execveat -F auid>=1000 -F auid!=-1 -k benign_exec

## 3. CAPTURE PRIVILEGE CHANGES (For Sudo/Rule-Based Baseline)
## Captures when they try to become root or change permissions.
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=-1 -k benign_priv
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=-1 -k benign_priv

## 4. CAPTURE FILE MODIFICATIONS (Specific High-Level)
## We capture explicit permission changes.
## (Capturing 'open' is too noisy for harvesting, chmod is better).
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown,fchown,fchownat -F auid>=1000 -F auid!=-1 -k benign_perm
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,chown,fchown,fchownat -F auid>=1000 -F auid!=-1 -k benign_perm

EOF

# 5. REGENERATE RULES AND RESTART
# This merges our new file into the master audit.rules
echo "[*] Regenerating audit rules..."
augenrules --load

echo "[*] Restarting auditd service..."
# Try systemd first, fallback to service command
if command -v systemctl &> /dev/null; then
    systemctl restart auditd
else
    service auditd restart
fi

# 6. VERIFICATION
echo "----------------------------------------------------"
echo "SETUP COMPLETE."
echo "Active rules:"
auditctl -l
echo "----------------------------------------------------"
echo "[!] Logs are now being recorded to /var/log/audit/audit.log"
echo "[!] This setup is persistent. It will run automatically on reboot."