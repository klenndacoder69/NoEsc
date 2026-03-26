#!/bin/bash
# Test Script: Verify Desktop Notifications are Working
# This creates a minimal test event that triggers an alert

echo "============================================"
echo "NoEsc Desktop Notification Test"
echo "============================================"
echo ""
echo "This will send a test SUID abuse alert."
echo "You should see a desktop notification appear!"
echo ""

# Create a minimal SUID abuse event (non-whitelisted path triggers alert)
cat << 'EOF' | ./noesc_daemon
type=SYSCALL msg=audit(1111111111.111:999): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd12345678 a1=7ffd12345680 a2=7ffd12345690 items=2 ppid=1000 pid=9999 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="test" exe="/tmp/evil_binary" key="benign_priv"
EOF

echo ""
echo "============================================"
echo "Test Complete!"
echo "============================================"
echo ""
echo "Check for:"
echo "  1. Desktop notification (should have appeared)"
echo "  2. Alert in: ./noesc_alerts.log"
echo "  3. Syslog entry: journalctl -t noesc -n 5"
echo ""
