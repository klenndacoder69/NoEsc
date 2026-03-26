#!/bin/bash
# Test: Multiple attack vectors simultaneously

echo "╔════════════════════════════════════════════════════════╗"
echo "║        Multi-Vector Test (All 3 Attacks at Once)      ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Triggering all 3 attack vectors simultaneously:"
echo "  1. SUID Abuse (CRITICAL)"
echo "  2. Sensitive File Tampering (CRITICAL)"
echo "  3. Sudo Misuse (INFO/WARNING/CRITICAL)"
echo ""
echo "You should see 3 different notifications!"
echo ""

cat << 'EVENTS' | ./noesc_daemon
type=SYSCALL msg=audit(2222222222.001:101): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 items=2 ppid=1000 pid=7001 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="suid_test" exe="/tmp/evil_suid" key="benign_priv"
type=SYSCALL msg=audit(2222222222.002:102): arch=c000003e syscall=257 success=yes exit=3 a0=/etc/shadow a1=2 a2=3 items=2 ppid=1000 pid=7002 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="vim" exe="/usr/bin/vim" key="identitychange"
type=USER_CMD msg=audit(2222222222.003:103): pid=7003 uid=1000 auid=1000 ses=1 msg='cwd="/home/user" cmd=636863777720313030302074657374 terminal=pts/0 res=failed'
type=SYSCALL msg=audit(2222222222.003:103): arch=c000003e syscall=59 success=yes exit=0 a0=chmod a1=1000 a2=test items=2 ppid=1000 pid=7003 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="chmod" exe="/usr/bin/chmod" key="benign_exec"
type=USER_CMD msg=audit(2222222222.004:104): pid=7004 uid=1000 auid=1000 ses=1 msg='cwd="/home/user" cmd=63686f776e20726f6f742074657374 terminal=pts/0 res=success'
type=SYSCALL msg=audit(2222222222.004:104): arch=c000003e syscall=59 success=yes exit=0 a0=chown a1=root a2=test items=2 ppid=1000 pid=7004 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="chown" exe="/usr/bin/chown" key="benign_exec"
type=USER_CMD msg=audit(2222222222.005:105): pid=7005 uid=1000 auid=1000 ses=1 msg='cwd="/home/user" cmd=636863777720313030302074657374 terminal=pts/0 res=success'
type=SYSCALL msg=audit(2222222222.005:105): arch=c000003e syscall=59 success=yes exit=0 a0=chmod a1=1000 a2=test items=2 ppid=1000 pid=7005 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="chmod" exe="/usr/bin/chmod" key="benign_exec"
type=USER_CMD msg=audit(2222222222.006:106): pid=7006 uid=1000 auid=1000 ses=1 msg='cwd="/home/user" cmd=63686f776e20726f6f742074657374 terminal=pts/0 res=success'
type=SYSCALL msg=audit(2222222222.006:106): arch=c000003e syscall=59 success=yes exit=0 a0=chown a1=root a2=test items=2 ppid=1000 pid=7006 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="chown" exe="/usr/bin/chown" key="benign_exec"
EVENTS

echo ""
echo "════════════════════════════════════════════════════════"
echo "How many notifications did you see?"
echo ""
echo "Expected: 3 notifications"
echo "  1. SUID Abuse (Red/Critical)"
echo "  2. File Tampering (Red/Critical)"
echo "  3. Sudo Misuse Score=20 (Red/Critical)"
echo "════════════════════════════════════════════════════════"

