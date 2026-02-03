#!/bin/bash

# NoEsc - Benign Data Harvesting Deployment Script (v2)
# Includes Auto-Installation of Dependencies
# Author: Klenn Jakek Borja

# 1. CHECK FOR ROOT
if [ "$EUID" -ne 0 ]; then 
  echo "[-] Please run as root (sudo ./deploy_harvest_v2.sh)"
  exit
fi

echo "[*] Starting NoEsc Harvest Setup..."

# ==========================================
# STEP 0: INSTALL DEPENDENCIES
# ==========================================
echo "[*] Checking for auditd installation..."

if ! command -v auditd &> /dev/null; then
    echo "[!] Auditd not found. Installing..."
    
    # Update package lists to ensure we find the package
    apt-get update -q
    
    # Install auditd silently (-y)
    apt-get install -y auditd audispd-plugins
    
    # Enable it to start on boot
    systemctl enable auditd
    systemctl start auditd
    
    echo "[+] Auditd installed successfully."
else
    echo "[+] Auditd is already installed."
fi

# ==========================================
# STEP 1: BACKUP CONFIGURATIONS
# ==========================================
# Only backup if the backup doesn't exist yet (to avoid overwriting original with a modified one)
if [ ! -f /etc/audit/auditd.conf.bak_noesc ]; then
    echo "[*] Backing up existing audit configurations..."
    cp /etc/audit/auditd.conf /etc/audit/auditd.conf.bak_noesc
    # Check if rules exist before backing up
    if [ -f /etc/audit/rules.d/audit.rules ]; then
        cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.bak_noesc
    fi
fi

# ==========================================
# STEP 2: CONFIGURE LOG ROTATION (SAFETY)
# ==========================================
echo "[*] Configuring Log Rotation (Safety limits)..."

# Ensure the file exists
touch /etc/audit/auditd.conf

# Set max log file size to 20MB
sed -i 's/^max_log_file =.*/max_log_file = 20/' /etc/audit/auditd.conf
# Keep only 5 rotated logs
sed -i 's/^num_logs =.*/num_logs = 5/' /etc/audit/auditd.conf
# When full, ROTATE
sed -i 's/^max_log_file_action =.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
# Ignore low disk space warnings (prevents syslog spam)
sed -i 's/^space_left_action =.*/space_left_action = IGNORE/' /etc/audit/auditd.conf

# ==========================================
# STEP 3: INJECT HARVESTING RULES
# ==========================================
echo "[*] Injecting Data Collection Rules..."

# Ensure rules directory exists
mkdir -p /etc/audit/rules.d/

cat > /etc/audit/rules.d/99-noesc-harvest.rules <<EOF
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
EOF

# ==========================================
# STEP 4: RESTART & VERIFY
# ==========================================
echo "[*] Regenerating audit rules..."
augenrules --load

echo "[*] Restarting auditd service..."
service auditd restart

echo "----------------------------------------------------"
echo "SETUP COMPLETE."
echo "Active rules:"
auditctl -l
echo "----------------------------------------------------"