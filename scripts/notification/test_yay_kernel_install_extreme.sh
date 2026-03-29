#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "NoEsc Extreme Kernel-Install Replay (30 Critical Cycles)"
echo "============================================================"

a=$(cd ../.. && pwd)
echo "[*] Workspace: $a"
echo "[*] Dataset: sample_set/yay_kernel_install_extreme.log"
echo "[*] Expected: WARNING=30, CRITICAL=30"

after_cmd="bash scripts/notification/test_yay_kernel_install_burst.sh sample_set/yay_kernel_install_extreme.log"
cd ../..
EXPECTED_WARN=30 EXPECTED_CRIT=30 $after_cmd
