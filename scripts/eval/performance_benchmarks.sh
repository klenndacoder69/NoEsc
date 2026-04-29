#!/usr/bin/env bash
# performance_benchmarks.sh — Macro performance overhead benchmark for NoEsc.
#
# Measures the wall-clock time of compiling the NoEsc daemon under two conditions:
#   1. Baseline: no audit rules loaded (auditd running, but no noesc rules)
#   2. With Rules: noesc audit rules active (99-noesc.rules loaded into kernel)
#
# Runs 5 trials per condition and outputs a CSV + summary table.
# Usage: sudo ./scripts/eval/performance_benchmarks.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RULES_FILE="$PROJECT_ROOT/config/noesc.rules"
RULES_DEST="/etc/audit/rules.d/99-noesc.rules"
NUM_RUNS=5
OUT_DIR="$PROJECT_ROOT/out/performance_benchmarks"
CSV_FILE="$OUT_DIR/macro_benchmark.csv"

if [ "$EUID" -ne 0 ]; then
    echo "[-] This script must be run as root (sudo $0)"
    exit 1
fi

if ! command -v auditctl >/dev/null 2>&1; then
    echo "[-] auditctl not found. Please install auditd."
    exit 1
fi

mkdir -p "$OUT_DIR"
cd "$PROJECT_ROOT"

echo "NoEsc Macro Benchmark — Wall-Clock Build Time"
echo "======================================================"
echo "  Workload : make clean && make (NoEsc daemon)"
echo "  Runs     : $NUM_RUNS per condition"
echo "  Output   : $CSV_FILE"
echo "======================================================"
echo ""

# Write CSV header
echo "condition,run,wall_clock_seconds" > "$CSV_FILE"

# Helper: run one timed build trial, return elapsed seconds
run_trial() {
    local condition="$1"
    local run_num="$2"
    make clean > /dev/null 2>&1
    local start
    start=$(date +%s%N)
    make > /dev/null 2>&1
    local end
    end=$(date +%s%N)
    local elapsed
    elapsed=$(python3 -c "print(f'{($end - $start) / 1_000_000_000:.4f}')")
    echo "$condition,$run_num,$elapsed" >> "$CSV_FILE"
    echo "    Run $run_num: ${elapsed}s"
}

# -------------------------------------------------------
# CONDITION 1: Baseline — flush all rules
# -------------------------------------------------------
echo "[*] Condition 1/2: Baseline (no NoEsc audit rules)"
# Flush any existing noesc rules for a clean baseline
auditctl -D > /dev/null 2>&1 || true
if [ -f "$RULES_DEST" ]; then
    mv "$RULES_DEST" "${RULES_DEST}.bak_bench"
fi
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load > /dev/null 2>&1 || true
fi
sleep 1

for i in $(seq 1 "$NUM_RUNS"); do
    run_trial "baseline" "$i"
done

# -------------------------------------------------------
# CONDITION 2: With NoEsc audit rules active
# -------------------------------------------------------
echo ""
echo "[*] Condition 2/2: With NoEsc audit rules active"
cp "$RULES_FILE" "$RULES_DEST"
chmod 640 "$RULES_DEST"
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load > /dev/null 2>&1 || true
fi
sleep 1

for i in $(seq 1 "$NUM_RUNS"); do
    run_trial "noesc_rules" "$i"
done

# -------------------------------------------------------
# Restore the rules file if it was backed up
# -------------------------------------------------------
if [ -f "${RULES_DEST}.bak_bench" ]; then
    mv "${RULES_DEST}.bak_bench" "$RULES_DEST"
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load > /dev/null 2>&1 || true
    fi
fi

# -------------------------------------------------------
# Summary calculation
# -------------------------------------------------------
echo ""
echo "[*] Computing summary..."

python3 - "$CSV_FILE" <<'PYEOF'
import csv, sys
from statistics import mean

data = {"baseline": [], "noesc_rules": []}
with open(sys.argv[1]) as f:
    reader = csv.DictReader(f)
    for row in reader:
        data[row["condition"]].append(float(row["wall_clock_seconds"]))

baseline_avg = mean(data["baseline"])
rules_avg    = mean(data["noesc_rules"])
overhead_pct = ((rules_avg - baseline_avg) / baseline_avg) * 100

print("")
print("====================================================")
print(" Macro Benchmark Summary (NoEsc Daemon Build Time)")
print("====================================================")
print(f" {'Condition':<30} {'Avg (s)':>10} {'Overhead':>10}")
print(f" {'-'*50}")
print(f" {'Baseline (no rules)':<30} {baseline_avg:>10.4f} {'—':>10}")
print(f" {'With NoEsc rules':<30} {rules_avg:>10.4f} {overhead_pct:>9.2f}%")
print("====================================================")
print(f" Results saved to: {sys.argv[1]}")
PYEOF
