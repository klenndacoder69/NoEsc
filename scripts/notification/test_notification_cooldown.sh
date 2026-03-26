#!/bin/bash
# Test: Cooldown system - will it trigger again after 10+ seconds?

echo "╔════════════════════════════════════════════════════════╗"
echo "║   NoEsc Cooldown Recovery Test (10-second wait)       ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "This test verifies:"
echo "  1. First alert triggers notification"
echo "  2. Rapid follow-ups are suppressed (cooldown)"
echo "  3. After 10+ seconds, notifications resume"
echo ""

# Event 1: Should trigger notification
cat << 'EVENT1' | ./noesc_daemon
type=SYSCALL msg=audit(1111111111.001:1): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=9001 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="test1" exe="/tmp/cooldown_test" key="benign_priv"
EVENT1

echo "✓ Alert 1 sent (should see notification)"
echo ""
echo "Waiting 3 seconds..."
sleep 3

# Event 2: Should be suppressed (within cooldown)
cat << 'EVENT2' | ./noesc_daemon
type=SYSCALL msg=audit(1111111114.001:2): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=9002 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="test2" exe="/tmp/cooldown_test" key="benign_priv"
EVENT2

echo "✓ Alert 2 sent (should be SUPPRESSED - no notification)"
echo ""
echo "Now waiting 12 seconds for cooldown to expire..."
sleep 12

# Event 3: Should trigger again (cooldown expired)
cat << 'EVENT3' | ./noesc_daemon
type=SYSCALL msg=audit(1111111127.001:3): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=9003 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="test3" exe="/tmp/cooldown_test" key="benign_priv"
EVENT3

echo "✓ Alert 3 sent (should see notification again)"
echo ""
echo "════════════════════════════════════════════════════════"
echo "Expected Results:"
echo "  Notification 1: YES (first alert)"
echo "  Notification 2: NO  (suppressed by cooldown)"
echo "  Notification 3: YES (cooldown expired)"
echo "════════════════════════════════════════════════════════"

