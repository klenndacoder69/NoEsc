#!/bin/bash

echo "==================================="
echo "NoEsc Quick Detection Test"
echo "==================================="
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Clean up
rm -f noesc_alerts.log /tmp/test_attack /tmp/test_attack.c

echo "[*] Working directory: $(pwd)"
echo "[*] Creating SUID test binary..."

# Create test binary
cat > /tmp/test_attack.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
int main() {
    printf("EUID=%d\n", geteuid());
    return 0;
}
EOF

gcc /tmp/test_attack.c -o /tmp/test_attack
sudo chown root:root /tmp/test_attack
sudo chmod u+s /tmp/test_attack

echo "[*] Executing attack..."
/tmp/test_attack

echo "[*] Feeding to NoEsc daemon..."
START_TIME=$(date -d '2 minutes ago' +%H:%M:%S)
sudo ausearch -ts $START_TIME --raw 2>/dev/null | ./noesc_daemon

echo ""
echo "==================================="
echo "DETECTION RESULTS:"
echo "==================================="

if [ -f noesc_alerts.log ]; then
    echo ""
    echo "✅ ATTACK DETECTED!"
    echo ""
    cat noesc_alerts.log
    echo ""
    
    PID=$(grep -oP 'pid=\K[0-9]+' noesc_alerts.log | head -1)
    if [ ! -z "$PID" ]; then
        echo "---"
        echo "Full forensics available:"
        echo "  sudo ausearch -p $PID -i"
        echo ""
    fi
else
    echo ""
    echo "⚠️  Log file not created (but check terminal output above)"
    echo ""
fi

# Cleanup
rm -f /tmp/test_attack /tmp/test_attack.c

echo "==================================="
