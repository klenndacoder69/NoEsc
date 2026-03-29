#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "NoEsc Mixed Update Replay (Varied Dangerous Commands)"
echo "============================================================"

a=$(cd ../.. && pwd)
echo "[*] Workspace: $a"
echo "[*] Dataset: sample_set/yay_kernel_install_mixed.log"
echo "[*] Expected: WARNING=12, CRITICAL=12"

after_cmd="bash scripts/notification/test_yay_kernel_install_burst.sh sample_set/yay_kernel_install_mixed.log"
cd ../..
EXPECTED_WARN=12 EXPECTED_CRIT=12 $after_cmd
