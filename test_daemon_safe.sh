#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "==================================="
echo "NoEsc Safe Test (No Rule Changes)"
echo "==================================="
echo ""

# Clean up old test data
rm -f noesc_alerts.log
rm -f /tmp/test_attack /tmp/test_attack.c

echo "[*] This script will:"
echo "    1. Create a SUID binary in /tmp (simulated attack)"
echo "    2. Execute it"
echo "    3. Feed your EXISTING audit log to NoEsc"
echo "    4. Show if NoEsc detected it"
echo ""
echo "[*] Your audit rules will NOT be changed!"
echo ""
read -p "Press ENTER to continue or Ctrl+C to cancel..."

# Create a SUID test binary
echo ""
echo "[1/3] Creating SUID test binary in /tmp..."
cat > /tmp/test_attack.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
int main() {
    printf("Test: EUID=%d (0 means SUID worked)\n", geteuid());
    return 0;
}
EOF

gcc /tmp/test_attack.c -o /tmp/test_attack
sudo chown root:root /tmp/test_attack
sudo chmod u+s /tmp/test_attack

echo "[2/3] Executing attack (running SUID binary)..."
/tmp/test_attack

echo "[3/3] Checking NoEsc detection..."
echo ""

# Get recent audit events (last 2 minutes)
START_TIME=$(date -d '2 minutes ago' +%H:%M:%S)

# Feed to daemon
sudo ausearch -ts $START_TIME --raw 2>/dev/null | ./noesc_daemon

# Clean up
rm -f /tmp/test_attack /tmp/test_attack.c

echo ""
echo "==================================="
echo "RESULTS:"
echo "==================================="

if [ -f noesc_alerts.log ] && [ -s noesc_alerts.log ]; then
    echo ""
    echo "✅ SUCCESS! NoEsc detected the attack:"
    echo ""
    cat noesc_alerts.log
    echo ""
    
    # Extract PID for investigation
    PID=$(grep -oP 'pid=\K[0-9]+' noesc_alerts.log | head -1)
    if [ ! -z "$PID" ]; then
        echo "---"
        echo "To see full forensic details, run:"
        echo "  sudo ausearch -p $PID -i"
        echo ""
    fi
else
    echo ""
    echo "❌ No alerts detected. Possible reasons:"
    echo ""
    echo "1. Check if auditd is running:"
    echo "   sudo systemctl status auditd"
    echo ""
    echo "2. Check if audit rules are capturing execve:"
    echo "   sudo auditctl -l | grep execve"
    echo ""
    echo "3. Check if events are in audit log:"
    echo "   sudo ausearch -ts $START_TIME -k priv_exec"
    echo "   (or)"
    echo "   sudo ausearch -ts $START_TIME | grep /tmp/test_attack"
    echo ""
    echo "4. If no rules exist, run harvest_logs.sh first:"
    echo "   sudo ./scripts/harvest_logs.sh"
    echo ""
fi

echo "==================================="
