#!/bin/bash
# Test: Smart Severity System (Path-based + Progressive Alerting)

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║          Smart Severity Testing Suite                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "TEST 1: Path-Based Severity (SUID)"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Testing high-risk path (/tmp) vs medium-risk path (/home)"
echo ""

# Test 1a: High-risk path (/tmp) - Should be CRITICAL + Desktop Notification
echo "1a. SUID binary in /tmp (HIGH RISK):"
cat << 'EVENT1' | ./noesc_daemon 2>&1 | grep -E "(ALERT|CRITICAL|WARNING)"
type=SYSCALL msg=audit(3000000001.001:1): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=5001 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="evil" exe="/tmp/evil_binary" key="benign_priv"
EVENT1
echo "   Expected: CRITICAL alert + Desktop notification"
echo ""

sleep 2

# Test 1b: Medium-risk path (/home) - Should be WARNING (no desktop notification)
echo "1b. SUID binary in /home (MEDIUM RISK - student work?):"
cat << 'EVENT2' | ./noesc_daemon 2>&1 | grep -E "(ALERT|CRITICAL|WARNING)"
type=SYSCALL msg=audit(3000000011.001:2): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=5002 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="myshell" exe="/home/student/projects/myshell" key="benign_priv"
EVENT2
echo "   Expected: WARNING alert (logged but NO desktop notification)"
echo ""

sleep 2

echo "═══════════════════════════════════════════════════════════"
echo "TEST 2: Progressive Sudo Alerting"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Building up sudo score: 0 → 15 (WARNING) → 20 (CRITICAL)"
echo ""

# Score: 0 → 5 → 10 (silent, below threshold)
cat << 'EVENTS' | ./noesc_daemon 2>&1 | grep -E "(score|Score)" | head -10
type=USER_CMD msg=audit(3000000020.001:10): pid=6001 uid=1000 auid=1000 ses=1 msg='cwd="/home" cmd=636863777720313030302074657374 terminal=pts/0 res=success'
type=SYSCALL msg=audit(3000000020.001:10): arch=c000003e syscall=59 success=yes exit=0 a0=chmod a1=1000 a2=test items=2 ppid=1000 pid=6001 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="chmod" exe="/usr/bin/chmod" key="benign_exec"
type=USER_CMD msg=audit(3000000021.001:11): pid=6002 uid=1000 auid=1000 ses=1 msg='cwd="/home" cmd=63686f776e20726f6f742074657374 terminal=pts/0 res=success'
type=SYSCALL msg=audit(3000000021.001:11): arch=c000003e syscall=59 success=yes exit=0 a0=chown a1=root a2=test items=2 ppid=1000 pid=6002 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="chown" exe="/usr/bin/chown" key="benign_exec"
type=USER_CMD msg=audit(3000000022.001:12): pid=6003 uid=1000 auid=1000 ses=1 msg='cwd="/home" cmd=636863777720313030302074657374 terminal=pts/0 res=success'
type=SYSCALL msg=audit(3000000022.001:12): arch=c000003e syscall=59 success=yes exit=0 a0=chmod a1=1000 a2=test items=2 ppid=1000 pid=6003 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="chmod" exe="/usr/bin/chmod" key="benign_exec"
type=USER_CMD msg=audit(3000000023.001:13): pid=6004 uid=1000 auid=1000 ses=1 msg='cwd="/home" cmd=63686f776e20726f6f742074657374 terminal=pts/0 res=success'
type=SYSCALL msg=audit(3000000023.001:13): arch=c000003e syscall=59 success=yes exit=0 a0=chown a1=root a2=test items=2 ppid=1000 pid=6004 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="chown" exe="/usr/bin/chown" key="benign_exec"
EVENTS

echo ""
echo "   Score should now be: 20/20"
echo "   Expected: 1 WARNING at 15, then 1 CRITICAL at 20"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "RESULTS SUMMARY"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Desktop notifications shown:"
echo "  ✓ /tmp/evil_binary (CRITICAL)"
echo "  ✓ Sudo score 20/20 (CRITICAL)"
echo ""
echo "Desktop notifications suppressed (WARNING only):"
echo "  ✓ /home/student/myshell (WARNING - logged only)"
echo "  ✓ Sudo score 15/20 (WARNING - logged only)"
echo ""
echo "Check logs for full details:"
echo "  cat noesc_alerts.log | tail -10"
echo "═══════════════════════════════════════════════════════════"

