#!/bin/bash
# Test: Will notifications spam or is cooldown working?

echo "╔════════════════════════════════════════════════════════╗"
echo "║     NoEsc Notification Spam Test (Cooldown Test)      ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Testing if cooldown prevents notification spam..."
echo "Expected: Only 1 notification per 10 seconds per vector"
echo ""

# Generate 10 rapid SUID abuse events (same user, same vector)
# Should only trigger 1 notification due to cooldown
cat << 'EVENTS' | ./noesc_daemon
type=SYSCALL msg=audit(1111111111.001:1): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=8001 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil1" exe="/tmp/spam1" key="benign_priv"
type=SYSCALL msg=audit(1111111111.002:2): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=8002 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil2" exe="/tmp/spam2" key="benign_priv"
type=SYSCALL msg=audit(1111111111.003:3): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=8003 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil3" exe="/tmp/spam3" key="benign_priv"
type=SYSCALL msg=audit(1111111111.004:4): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=8004 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil4" exe="/tmp/spam4" key="benign_priv"
type=SYSCALL msg=audit(1111111111.005:5): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=8005 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil5" exe="/tmp/spam5" key="benign_priv"
type=SYSCALL msg=audit(1111111111.006:6): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=8006 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil6" exe="/tmp/spam6" key="benign_priv"
type=SYSCALL msg=audit(1111111111.007:7): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=8007 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil7" exe="/tmp/spam7" key="benign_priv"
type=SYSCALL msg=audit(1111111111.008:8): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=8008 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil8" exe="/tmp/spam8" key="benign_priv"
type=SYSCALL msg=audit(1111111111.009:9): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=8009 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil9" exe="/tmp/spam9" key="benign_priv"
type=SYSCALL msg=audit(1111111111.010:10): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=8010 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil10" exe="/tmp/spam10" key="benign_priv"
EVENTS

echo ""
echo "════════════════════════════════════════════════════════"
echo "Result: Did you see 1 notification or 10?"
echo ""
echo "✓ If you saw 1 notification  → Cooldown is working!"
echo "✗ If you saw 10 notifications → Cooldown is broken!"
echo "════════════════════════════════════════════════════════"

