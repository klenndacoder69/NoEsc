#!/bin/bash

# NoEsc malicious dataset harvesting wrapper.

set -u

OUT_DIR="sample_set/training_data/malicious"
OUT_FILE="${OUT_DIR}/malicious_parsed.json"

echo "==============================================="
echo "NoEsc Malicious Data Harvest"
echo "==============================================="

NOESC_LAB_PASSWORD="${NOESC_LAB_PASSWORD:-}"
NOESC_FAILED_SUDO_MIN="${NOESC_FAILED_SUDO_MIN:-1}"
NOESC_FAILED_SUDO_MAX="${NOESC_FAILED_SUDO_MAX:-2}"
NOESC_BREAKOUT_RUNS="${NOESC_BREAKOUT_RUNS:-5}"
NOESC_APPEND_OUTPUT="${NOESC_APPEND_OUTPUT:-0}"
NOESC_TARGET_LINES="${NOESC_TARGET_LINES:-0}"
NOESC_MAX_BATCHES="${NOESC_MAX_BATCHES:-200}"

if ! [[ "$NOESC_BREAKOUT_RUNS" =~ ^[0-9]+$ ]] || [ "$NOESC_BREAKOUT_RUNS" -lt 1 ]; then
  echo "[-] NOESC_BREAKOUT_RUNS must be an integer >= 1"
  exit 1
fi

if [ "$NOESC_APPEND_OUTPUT" != "0" ] && [ "$NOESC_APPEND_OUTPUT" != "1" ]; then
  echo "[-] NOESC_APPEND_OUTPUT must be 0 (overwrite) or 1 (append)"
  exit 1
fi

if ! [[ "$NOESC_TARGET_LINES" =~ ^[0-9]+$ ]]; then
  echo "[-] NOESC_TARGET_LINES must be an integer >= 0"
  exit 1
fi

if ! [[ "$NOESC_MAX_BATCHES" =~ ^[0-9]+$ ]] || [ "$NOESC_MAX_BATCHES" -lt 1 ]; then
  echo "[-] NOESC_MAX_BATCHES must be an integer >= 1"
  exit 1
fi

if [ ! -x "./noesc_daemon" ]; then
  echo "[-] Missing executable ./noesc_daemon in project root."
  exit 1
fi

if [ ! -x "./setup_lab_vulns.sh" ] || [ ! -x "./execute_lab_breakout.sh" ]; then
  echo "[-] Missing executable setup/execute lab scripts in project root."
  exit 1
fi

if [ -z "$NOESC_LAB_PASSWORD" ]; then
  read -r -s -p "[?] Optional: enter your sudo password once for non-interactive runs (press Enter to skip): " NOESC_LAB_PASSWORD
  echo ""
fi

if [ -n "$NOESC_LAB_PASSWORD" ]; then
  if printf '%s\n' "$NOESC_LAB_PASSWORD" | sudo -S -p '' -v > /dev/null 2>&1; then
    echo "[*] Validated NOESC_LAB_PASSWORD for non-interactive breakout re-auth"
  else
    echo "[!] NOESC_LAB_PASSWORD validation failed; continuing with interactive sudo prompts"
    NOESC_LAB_PASSWORD=""
  fi
fi

export NOESC_LAB_PASSWORD
export NOESC_FAILED_SUDO_MIN
export NOESC_FAILED_SUDO_MAX
export NOESC_BREAKOUT_RUNS

run_with_sudo() {
  if [ -n "$NOESC_LAB_PASSWORD" ]; then
    printf '%s\n' "$NOESC_LAB_PASSWORD" | sudo -S -p '' "$@"
  else
    sudo "$@"
  fi
}

line_count() {
  if [ -f "$OUT_FILE" ]; then
    wc -l < "$OUT_FILE"
  else
    echo 0
  fi
}

run_one_batch() {
  local batch_num="$1"

  echo ""
  echo "[*] ===== Harvest Batch ${batch_num} ====="

  echo "[*] Step 2/7 - Truncating /var/log/audit/audit.log"
  run_with_sudo sh -c ': > /var/log/audit/audit.log' || {
    echo "[-] Could not truncate /var/log/audit/audit.log"
    exit 1
  }

  echo "[*] Step 3/7 - Planting Vector 1 lab vulnerability"
  run_with_sudo ./setup_lab_vulns.sh || {
    echo "[-] setup_lab_vulns.sh failed"
    exit 1
  }

  echo "[*] Step 4/7 - Executing randomized breakout runs (x${NOESC_BREAKOUT_RUNS})"
  for i in $(seq 1 "$NOESC_BREAKOUT_RUNS"); do
    echo "    -> Run $i/${NOESC_BREAKOUT_RUNS}"
    ./execute_lab_breakout.sh || {
      echo "[-] execute_lab_breakout.sh failed at run $i"
      exit 1
    }
  done

  echo "[*] Waiting 3s for auditd flush"
  sleep 3

  echo "[*] Step 5/7 - Parsing fresh malicious audit log with NoEsc"
  tmp_out="$(mktemp)"
  run_with_sudo cat /var/log/audit/audit.log | ./noesc_daemon --dump-json > "$tmp_out" 2> /dev/null
  if [ ! -s "$tmp_out" ]; then
    rm -f "$tmp_out"
    echo "[-] Parsed output is empty; check audit capture and daemon parsing"
    exit 1
  fi

  batch_lines="$(wc -l < "$tmp_out")"

  if [ "$NOESC_APPEND_OUTPUT" = "1" ] && [ -f "$OUT_FILE" ]; then
    cat "$tmp_out" >> "$OUT_FILE"
    rm -f "$tmp_out"
  else
    mv "$tmp_out" "$OUT_FILE"
  fi

  echo "[*] Step 6/7 - Fixing ownership"
  run_with_sudo chown "$USER:$USER" "$OUT_FILE"

  total_lines="$(line_count)"
  echo "[*] Batch ${batch_num} added ${batch_lines} events (total: ${total_lines})"
}

echo "[*] Step 1/7 - Ensuring output directory exists"
mkdir -p "$OUT_DIR"

if [ "$NOESC_TARGET_LINES" -gt 0 ]; then
  # Target mode accumulates multiple harvest batches until line goal is reached.
  if [ "$NOESC_APPEND_OUTPUT" != "1" ]; then
    echo "[*] NOESC_TARGET_LINES is set; forcing append mode"
    NOESC_APPEND_OUTPUT="1"
  fi

  current_lines="$(line_count)"
  echo "[*] Target mode enabled: goal=${NOESC_TARGET_LINES}, current=${current_lines}, max_batches=${NOESC_MAX_BATCHES}"

  if [ "$current_lines" -ge "$NOESC_TARGET_LINES" ]; then
    echo "[+] Target already met. Current total is ${current_lines} lines."
    exit 0
  fi

  batch=0
  while [ "$current_lines" -lt "$NOESC_TARGET_LINES" ]; do
    batch=$((batch + 1))
    if [ "$batch" -gt "$NOESC_MAX_BATCHES" ]; then
      echo "[-] Reached NOESC_MAX_BATCHES (${NOESC_MAX_BATCHES}) before hitting target (${NOESC_TARGET_LINES})"
      exit 1
    fi

    run_one_batch "$batch"
    current_lines="$(line_count)"
    echo "[*] Progress: ${current_lines}/${NOESC_TARGET_LINES}"
  done

  echo ""
  echo "[+] Target reached with ${current_lines} JSON events in $OUT_FILE"
else
  run_one_batch 1
  final_lines="$(line_count)"
  echo ""
  echo "[*] Step 7/7 - Harvest complete"
  echo "[+] Wrote $OUT_FILE with $final_lines JSON events"
fi
