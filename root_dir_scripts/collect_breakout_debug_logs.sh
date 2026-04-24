#!/bin/bash

# Collects reproducible diagnostics for execute_lab_breakout sudo/PAM failures.

set -u

LOG_ROOT="sample_set/training_data/malicious/debug_logs"
RUN_STAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${LOG_ROOT}/run_${RUN_STAMP}"

mkdir -p "$RUN_DIR"

echo "==============================================="
echo "NoEsc Breakout Debug Collector"
echo "==============================================="
echo "[*] Run directory: $RUN_DIR"

if [ ! -x "./execute_lab_breakout.sh" ]; then
  echo "[-] Missing executable ./execute_lab_breakout.sh"
  exit 1
fi

NOESC_LAB_PASSWORD="${NOESC_LAB_PASSWORD:-}"
if [ -z "$NOESC_LAB_PASSWORD" ]; then
  read -r -s -p "[?] Optional: enter your sudo password once for non-interactive debug run (press Enter to skip): " NOESC_LAB_PASSWORD
  echo ""
fi
export NOESC_LAB_PASSWORD

# Keep one consolidated script transcript.
exec > >(tee -a "$RUN_DIR/session.log") 2>&1

echo "[*] Host/user context"
echo "    Date: $(date -Is)"
echo "    User: $USER"
echo "    PWD:  $(pwd)"
id
groups

echo "[*] Collecting sudo policy snapshot"
sudo -n true > /dev/null 2>&1 || true
sudo -l > "$RUN_DIR/sudo_l.txt" 2>&1 || true
sudo -V > "$RUN_DIR/sudo_version.txt" 2>&1 || true

echo "[*] Collecting PAM/sudo lockout related config"
sudo sh -c 'grep -R "pam_faillock\\|pam_tally2\\|deny=" /etc/pam.d /etc/security/faillock.conf 2>/dev/null || true' > "$RUN_DIR/pam_lockout_config.txt"
sudo sh -c 'grep -R "targetpw\\|rootpw\\|runaspw\\|timestamp_timeout" /etc/sudoers /etc/sudoers.d 2>/dev/null || true' > "$RUN_DIR/sudoers_auth_flags.txt"

echo "[*] Capturing pre-run sudo lock state"
sudo sh -c "faillock --user '$USER' 2>/dev/null || true" > "$RUN_DIR/faillock_before.txt"

echo "[*] Resetting sudo ticket so behavior is reproducible"
sudo -k || true

SINCE_TS="$(date '+%Y-%m-%d %H:%M:%S')"
echo "[*] Log capture baseline time: $SINCE_TS"

echo "[*] Running one traced breakout attempt (timeout 180s)"
set +e
timeout 180 bash -x ./execute_lab_breakout.sh > "$RUN_DIR/execute_stdout.log" 2> "$RUN_DIR/execute_stderr.log"
EXEC_RC=$?
set -e

echo "[*] Breakout exit code: $EXEC_RC" | tee "$RUN_DIR/execute_exit_code.txt"
if [ "$EXEC_RC" -eq 124 ]; then
  echo "[!] Breakout timed out after 180 seconds" | tee -a "$RUN_DIR/execute_exit_code.txt"
fi

echo "[*] Capturing post-run sudo lock state"
sudo sh -c "faillock --user '$USER' 2>/dev/null || true" > "$RUN_DIR/faillock_after.txt"

echo "[*] Exporting recent audit and journal logs"
sudo tail -n 1200 /var/log/audit/audit.log > "$RUN_DIR/audit_tail.log" 2>&1 || true
sudo journalctl --since "$SINCE_TS" _COMM=sudo > "$RUN_DIR/journal_sudo.log" 2>&1 || true
sudo journalctl --since "$SINCE_TS" | grep -Ei 'sudo|pam|faillock|unix_chkpwd|authentication' > "$RUN_DIR/journal_auth_filtered.log" 2>&1 || true

echo "[*] Writing quick triage summary"
{
  echo "run_dir=$RUN_DIR"
  echo "execute_exit_code=$EXEC_RC"
  echo "failed_user_auth_events_in_audit=$(grep -c \"res=failed\" \"$RUN_DIR/audit_tail.log\" 2>/dev/null || echo 0)"
  echo "sudo_password_prompts_seen=$(grep -c \"password\" \"$RUN_DIR/execute_stderr.log\" 2>/dev/null || echo 0)"
} > "$RUN_DIR/summary.txt"

echo "[+] Done. Collected logs in: $RUN_DIR"
echo "    - session.log"
echo "    - execute_stdout.log"
echo "    - execute_stderr.log"
echo "    - audit_tail.log"
echo "    - journal_sudo.log"
echo "    - journal_auth_filtered.log"
echo "    - summary.txt"
