#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/../.."

TEST_LOG="${1:-sample_set/yay_kernel_install_like.log}"
STDERR_CAPTURE="/tmp/noesc_yay_burst_replay.out"
EXPECTED_WARN="${EXPECTED_WARN:-10}"
EXPECTED_CRIT="${EXPECTED_CRIT:-10}"

if [ ! -f "$TEST_LOG" ]; then
  echo "[!] Missing test log: $TEST_LOG"
  exit 1
fi

rm -f noesc_alerts.log

echo "============================================================"
echo "NoEsc Yay/Kernel-Install Burst Replay"
echo "============================================================"
echo ""
echo "[*] This replays synthetic cp-heavy update-like events."
echo "[*] Scoring should use benign_exec launch events only."
echo "[*] benign_perm internal syscall noise should not add score."
echo "[*] Expected high-trigger cycles: ${EXPECTED_CRIT} CRITICAL events."
echo ""
echo "[*] Running daemon replay..."
./noesc_daemon < "$TEST_LOG" 2>&1 | tee "$STDERR_CAPTURE" >/dev/null

echo ""
echo "[*] Replay complete. Summarizing alerts from noesc_alerts.log"
if [ ! -f noesc_alerts.log ]; then
  echo "[!] noesc_alerts.log was not generated in workspace root."
  echo "    If daemon wrote to /var/log/noesc_alerts.log, inspect it there."
  exit 1
fi

sudo_lines=$(grep -c "SudoMisuse" noesc_alerts.log || true)
warn_lines=$(grep -c "WARNING ALERT \[SudoMisuse\]" noesc_alerts.log || true)
crit_lines=$(grep -c "CRITICAL ALERT \[SudoMisuse\]" noesc_alerts.log || true)

printf "    SudoMisuse total lines : %s\n" "$sudo_lines"
printf "    SudoMisuse WARNING     : %s\n" "$warn_lines"
printf "    SudoMisuse CRITICAL    : %s\n" "$crit_lines"

echo ""
echo "Expected with this replay data:"
echo "  - WARNING count = ${EXPECTED_WARN}"
echo "  - CRITICAL count = ${EXPECTED_CRIT}"

if [ "$warn_lines" = "$EXPECTED_WARN" ] && [ "$crit_lines" = "$EXPECTED_CRIT" ]; then
  echo "  ✓ Counts match expected values"
else
  echo "  ✗ Counts differ from expected values"
fi
echo ""
echo "Desktop notification expectation (if not in maintenance mode):"
echo "  1) First CRITICAL popup shown"
echo "  2) Next CRITICAL in same 30s window suppressed"
echo "  3) After rollover: one Burst Summary popup + one CRITICAL popup"
echo ""
echo "Tip: make sure maintenance mode file is absent or expired:"
echo "  /etc/noesc/sudo_maintenance_mode.until"
echo ""
echo "Recent SudoMisuse lines:"
grep "SudoMisuse" noesc_alerts.log | tail -n 8 || true

echo ""
echo "Done."
