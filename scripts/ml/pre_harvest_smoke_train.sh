#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ -x ".venv/bin/python" ]]; then
  PYTHON_BIN=".venv/bin/python"
else
  PYTHON_BIN="python3"
fi

BENIGN_DIR="sample_set/ml_smoke/benign"
MALICIOUS_DIR="sample_set/ml_smoke/malicious"
OUT_DIR="models/smoke_user_auth"

if [[ ! -d "$BENIGN_DIR" || ! -d "$MALICIOUS_DIR" ]]; then
  echo "[-] Missing smoke dataset directories."
  echo "    Expected: $BENIGN_DIR and $MALICIOUS_DIR"
  exit 1
fi

if [[ -z "$(find "$BENIGN_DIR" -type f 2>/dev/null)" ]]; then
  echo "[-] No smoke benign files found in $BENIGN_DIR"
  exit 1
fi

if [[ -z "$(find "$MALICIOUS_DIR" -type f 2>/dev/null)" ]]; then
  echo "[-] No smoke malicious files found in $MALICIOUS_DIR"
  exit 1
fi

mkdir -p "$OUT_DIR"

echo "[*] Running pre-harvest smoke training (SYSCALL + USER_AUTH contract)..."
"$PYTHON_BIN" src/ml_engine/train_model.py \
  --malicious-dir "$MALICIOUS_DIR" \
  --benign-dir "$BENIGN_DIR" \
  --model-out "$OUT_DIR/svm_model.pkl" \
  --vectorizer-out "$OUT_DIR/tfidf_vectorizer.pkl" \
  --metadata-out "$OUT_DIR/training_metadata.json" \
  --train-ratio 0.7 \
  --min-events-per-sequence 2

echo "[+] Smoke training complete. Artifacts in $OUT_DIR"
