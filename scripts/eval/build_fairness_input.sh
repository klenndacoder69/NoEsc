#!/usr/bin/env bash
# build_fairness_input.sh — Assemble a mixed benign + attack audit log for
# fairness comparison between ML-only and Rules-only engines.
#
# The existing audit.log.1 is a real university lab capture (benign only).
# The attack samples are in separate files. This script interleaves them to
# produce a single audit log that exercises BOTH engines.
#
# Usage: ./scripts/eval/build_fairness_input.sh [output_path]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${1:-${ROOT}/sample_set/fairness_input.log}"

BENIGN_LOG="${ROOT}/sample_set/audit.log.1"
ATTACK_SIM="${ROOT}/sample_set/attack_simulation.log"
SUDO_MISUSE="${ROOT}/sample_set/sudo_misuse.log"
PPID_ATTACKS="${ROOT}/sample_set/ppid_attacks.log"
SUDO_AUTH="${ROOT}/sample_set/sudo_auth.log"

missing=()
for f in "$BENIGN_LOG" "$ATTACK_SIM" "$SUDO_MISUSE" "$PPID_ATTACKS" "$SUDO_AUTH"; do
  if [ ! -f "$f" ]; then
    missing+=("$f")
  fi
done

if [ ${#missing[@]} -gt 0 ]; then
  echo "[!] Missing input files:"
  for f in "${missing[@]}"; do
    echo "    $f"
  done
  exit 1
fi

echo "[*] Building fairness comparison input log"
echo "    Benign source : $BENIGN_LOG"
echo "    Attack sources: attack_simulation.log, sudo_misuse.log, ppid_attacks.log, sudo_auth.log"
echo "    Output        : $OUTPUT"

# Strategy: Place the full benign log first, then append attack events.
# This simulates a realistic scenario: long period of benign activity followed
# by an attack campaign. Both engines process the same stream.
#
# Note: We strip comment lines from attack files to keep only parseable audit lines.

{
  # Full benign log (90,713 lines)
  cat "$BENIGN_LOG"

  echo ""
  echo "# === NoEsc Fairness: Attack Events Below ==="
  echo ""

  # Vector 1: SUID abuse (3 attack events + benign controls)
  grep -v '^#' "$ATTACK_SIM" | grep -v '^$'

  # Vector 2: Sudo misuse (stateful scoring)
  grep -v '^#' "$SUDO_MISUSE" | grep -v '^$'

  # Vector 1 variants: PPID-based SUID abuse
  grep -v '^#' "$PPID_ATTACKS" | grep -v '^$'

  # USER_AUTH events (for ML contextual features)
  grep -v '^#' "$SUDO_AUTH" | grep -v '^$'

} > "$OUTPUT"

total_lines=$(wc -l < "$OUTPUT")
benign_lines=$(wc -l < "$BENIGN_LOG")
attack_lines=$((total_lines - benign_lines))

echo "[+] Built fairness input: $total_lines total lines ($benign_lines benign + $attack_lines attack/comment)"
echo "[+] Output: $OUTPUT"
