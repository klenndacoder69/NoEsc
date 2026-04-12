#!/bin/bash

# NoEsc benign dataset harvesting wrapper.

set -u
set -o pipefail

COLLECTION_ROOT="${NOESC_COLLECTION_ROOT:-sample_set/NoEsc_Collection}"
OUT_FILE="${NOESC_BENIGN_OUT:-sample_set/training_data/benign/benign_parsed.json}"
NOESC_APPEND_OUTPUT="${NOESC_APPEND_OUTPUT:-0}"

echo "==============================================="
echo "NoEsc Benign Data Harvest"
echo "==============================================="

if [ ! -x "./noesc_daemon" ]; then
  echo "[-] Missing executable ./noesc_daemon in project root."
  exit 1
fi

if [ ! -d "$COLLECTION_ROOT" ]; then
  echo "[-] Collection directory not found: $COLLECTION_ROOT"
  exit 1
fi

if [ "$NOESC_APPEND_OUTPUT" != "0" ] && [ "$NOESC_APPEND_OUTPUT" != "1" ]; then
  echo "[-] NOESC_APPEND_OUTPUT must be 0 (overwrite) or 1 (append)"
  exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"

if [ "$NOESC_APPEND_OUTPUT" = "0" ]; then
  : > "$OUT_FILE"
  echo "[*] Output mode: overwrite"
else
  touch "$OUT_FILE"
  echo "[*] Output mode: append"
fi

success_files=0
failed_files=0
processed_files=0

while IFS= read -r -d '' log_file; do
  processed_files=$((processed_files + 1))
  echo "[*] Parsing ($processed_files): $log_file"

  before_lines=$(wc -l < "$OUT_FILE" 2>/dev/null || echo 0)

  if cat "$log_file" > /dev/null 2>&1; then
    if ! cat "$log_file" | ./noesc_daemon --dump-json >> "$OUT_FILE" 2> /dev/null; then
      echo "[!] Failed to parse: $log_file"
      failed_files=$((failed_files + 1))
      continue
    fi
  else
    if ! sudo cat "$log_file" | ./noesc_daemon --dump-json >> "$OUT_FILE" 2> /dev/null; then
      echo "[!] Failed to read/parse with sudo: $log_file"
      failed_files=$((failed_files + 1))
      continue
    fi
  fi

  after_lines=$(wc -l < "$OUT_FILE" 2>/dev/null || echo 0)
  added_lines=$((after_lines - before_lines))
  echo "    Added lines: $added_lines"
  success_files=$((success_files + 1))
done < <(
  find "$COLLECTION_ROOT" -type f \
    -path '*/var/log/audit/*' \
    \( -name 'audit.log' -o -name 'audit.log.[0-9]*' \) \
    -print0 | sort -z
)

if [ "$processed_files" -eq 0 ]; then
  echo "[-] No audit logs found under: $COLLECTION_ROOT"
  exit 1
fi

total_lines=$(wc -l < "$OUT_FILE" 2>/dev/null || echo 0)

echo ""
echo "[+] Benign harvest complete"
echo "    Collection root: $COLLECTION_ROOT"
echo "    Output file:     $OUT_FILE"
echo "    Files parsed:    $success_files"
echo "    Files failed:    $failed_files"
echo "    Total lines:     $total_lines"

if [ "$success_files" -eq 0 ]; then
  exit 1
fi

exit 0