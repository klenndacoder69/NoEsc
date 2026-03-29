#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/../.."

DATASET="${1:-sample_set/yay_kernel_install_extreme_10s.log}"

if [ ! -f "$DATASET" ]; then
  echo "[!] Missing dataset: $DATASET"
  echo "    Try one of:"
  echo "    - sample_set/yay_kernel_install_extreme_10s.log"
  echo "    - sample_set/yay_kernel_install_extreme_10s_dense.log"
  exit 1
fi

echo "============================================================"
echo "NoEsc Realtime 10s Replay"
echo "============================================================"
echo "[*] Dataset: $DATASET"
echo "[*] Feeding events in wall-clock timing from audit timestamps"
echo ""

awk '
match($0,/audit\(([0-9]+\.[0-9]+):/,m) {
  t = m[1] + 0
  if (prev != "") {
    dt = t - prev
    if (dt > 0) system("sleep " dt)
  }
  prev = t
}
{ print }
' "$DATASET" | ./noesc_daemon

echo ""
echo "Done."