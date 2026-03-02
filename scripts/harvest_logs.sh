#!/bin/bash

# NoEsc - Benign Data Harvesting Deployment Script (v2)
# Includes Auto-Installation of Dependencies
# Author: Klenn Jakek Borja

# 1. CHECK FOR ROOT
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./harvest_logs.sh)"
  echo "[-] Or use chmod +x and run the program"
  exit
fi

echo "[*] Starting NoEsc Harvest Setup..."

# step 0: setup
# Installing necessary dependencies
echo "[*] Checking for auditd installation..."

# take note that these commands are to be used only in an Ubuntu environment which the LAB PCs currently have
if ! command -v auditd &>/dev/null; then
  echo "[!] Auditd not found. Installing..."

  apt-get update -q

  # install auditd
  apt-get install -y auditd audispd-plugins

  # Enable it to start on boot
  systemctl enable auditd
  systemctl start auditd

  echo "[+] Auditd installed successfully."
else
  echo "[+] Auditd is already installed."
fi

# step 1: backup
# check if a backup exists, if not create.
if [ ! -f /etc/audit/auditd.conf.bak_noesc ]; then
  echo "[*] Backing up existing audit configurations..."
  cp /etc/audit/auditd.conf /etc/audit/auditd.conf.bak_noesc
  # Check if rules exist before backing up
  if [ -f /etc/audit/rules.d/audit.rules ]; then
    cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.bak_noesc
  fi
fi

# we need to create a log rotation to ensure that the service still runs afterwards
echo "[*] Configuring Log Rotation (Safety limits)..."

# Ensure the file exists
touch /etc/audit/auditd.conf

# set max log file to 50 (Optimized for ML Dataset)
sed -i 's/^max_log_file =.*/max_log_file = 50/' /etc/audit/auditd.conf

# a maximum of 10 logs should only be considered (500MB Total Buffer)
sed -i 's/^num_logs =.*/num_logs = 10/' /etc/audit/auditd.conf

# rotate when full
sed -i 's/^max_log_file_action =.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf

# ignore space left
sed -i 's/^space_left_action =.*/space_left_action = IGNORE/' /etc/audit/auditd.conf

# rules needed for harvesting and collating data
echo "[*] Injecting Data Collection Rules..."

# check if folder exists then add the rules
mkdir -p /etc/audit/rules.d/

cat >/etc/audit/rules.d/99-noesc-harvest.rules <<EOF
## NoEsc Harvesting Rules
-D
-b 8192
-f 1

## --- RULESET ---

## 1. CAPTURE COMMAND EXECUTION (For N-Gram/ML)
## Only capture Human Users (auid >= 1000)
-a always,exit -F arch=b64 -S execve,execveat -F auid>=1000 -F auid!=-1 -k benign_exec
-a always,exit -F arch=b32 -S execve,execveat -F auid>=1000 -F auid!=-1 -k benign_exec

## 2. CAPTURE PRIVILEGE CHANGES
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=-1 -k benign_priv
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=-1 -k benign_priv

## 3. CAPTURE PERMISSION CHANGES
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown,fchown,fchownat -F auid>=1000 -F auid!=-1 -k benign_perm
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,chown,fchown,fchownat -F auid>=1000 -F auid!=-1 -k benign_perm

## 4. SENSITIVE FILE WATCHES (Targeted Tampering Detection)
-w /etc/passwd -p wa -k identitychange
-w /etc/shadow -p wa -k identitychange
-w /etc/sudoers -p wa -k sudochange
EOF

# restart
echo "[*] Regenerating audit rules..."
augenrules --load

echo "[*] Restarting auditd service..."
service auditd restart

echo "----------------------------------------------------"
echo "SETUP COMPLETE."
echo "Active rules:"
auditctl -l
echo "----------------------------------------------------"
