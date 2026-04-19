#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="/home/swuffles/Documents/NoEsc/.venv/bin/python"

SHORT_DATA_DIR="sample_set/short_windows"
BENIGN_FILE="${SHORT_DATA_DIR}/benign/short_windows.json"
MALICIOUS_FILE="${SHORT_DATA_DIR}/malicious/short_windows.json"
OUT_DIR="models/short_v1"
MAX_PIDS_PER_CLASS="${NOESC_SHORT_MAX_PIDS_PER_CLASS:-50000}"

mkdir -p "$OUT_DIR"

echo "[*] Building short-window dataset..."
"$PYTHON_BIN" scripts/ml/build_short_window_dataset.py \
  --out-dir "$SHORT_DATA_DIR" \
  --min-syscalls 1 \
  --max-syscalls 2 \
  --max-pids-per-class "$MAX_PIDS_PER_CLASS"

if [[ ! -f "$BENIGN_FILE" || ! -f "$MALICIOUS_FILE" ]]; then
  echo "[-] Missing short-window dataset outputs"
  exit 1
fi

echo "[*] Training short-window companion model..."
"$PYTHON_BIN" src/ml_engine/train_model.py \
  --malicious-dir "${SHORT_DATA_DIR}/malicious" \
  --benign-dir "${SHORT_DATA_DIR}/benign" \
  --model-out "${OUT_DIR}/svm_model.pkl" \
  --vectorizer-out "${OUT_DIR}/tfidf_vectorizer.pkl" \
  --metadata-out "${OUT_DIR}/training_metadata.json" \
  --train-ratio 0.7 \
  --min-events-per-sequence 1

echo "[+] Short-window model training complete: ${OUT_DIR}"
