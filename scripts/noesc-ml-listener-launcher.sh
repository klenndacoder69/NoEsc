#!/bin/bash
set -euo pipefail

PROJECT_ROOT="${NOESC_PROJECT_ROOT:-/opt/noesc}"
if [[ ! -d "$PROJECT_ROOT" && -d "/home/swuffles/Documents/NoEsc" ]]; then
  PROJECT_ROOT="/home/swuffles/Documents/NoEsc"
fi

if [[ ! -d "$PROJECT_ROOT" ]]; then
  echo "[-] NOESC_PROJECT_ROOT not found: $PROJECT_ROOT" >&2
  exit 1
fi

PYTHON_BIN="${NOESC_PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$PROJECT_ROOT/.venv/bin/python" ]]; then
    PYTHON_BIN="$PROJECT_ROOT/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

SOCKET_PATH="${NOESC_SOCKET_PATH:-/tmp/noesc_ml.sock}"
SHORT_SEQ_POLICY="${NOESC_SHORT_SEQ_POLICY:-infer}"
SHORT_MODEL_MAX_SEQ_LEN="${NOESC_SHORT_MODEL_MAX_SEQ_LEN:-2}"
SHORT_MODEL_ENABLED="${NOESC_SHORT_MODEL_ENABLED:-1}"
SHORT_MAL_THRESHOLD="${NOESC_SHORT_MALICIOUS_SCORE_THRESHOLD:-0.5}"

cd "$PROJECT_ROOT"

args=(
  "--socket-path" "$SOCKET_PATH"
  "--short-seq-policy" "$SHORT_SEQ_POLICY"
  "--emit-benign"
  "--emit-auth-only"
)

if [[ -n "${NOESC_MODEL_PATH:-}" ]]; then
  args+=("--model-path" "$NOESC_MODEL_PATH")
fi
if [[ -n "${NOESC_VECTORIZER_PATH:-}" ]]; then
  args+=("--vectorizer-path" "$NOESC_VECTORIZER_PATH")
fi
if [[ -n "${NOESC_METADATA_PATH:-}" ]]; then
  args+=("--metadata-path" "$NOESC_METADATA_PATH")
fi

if [[ "$SHORT_MODEL_ENABLED" == "1" || "$SHORT_MODEL_ENABLED" == "true" || "$SHORT_MODEL_ENABLED" == "yes" ]]; then
  args+=("--short-model-enabled")
  args+=("--short-model-max-seq-len" "$SHORT_MODEL_MAX_SEQ_LEN")

  if [[ -n "${NOESC_SHORT_MODEL_PATH:-}" ]]; then
    args+=("--short-model-path" "$NOESC_SHORT_MODEL_PATH")
  fi
  if [[ -n "${NOESC_SHORT_VECTORIZER_PATH:-}" ]]; then
    args+=("--short-vectorizer-path" "$NOESC_SHORT_VECTORIZER_PATH")
  fi
  if [[ -n "${NOESC_SHORT_METADATA_PATH:-}" ]]; then
    args+=("--short-metadata-path" "$NOESC_SHORT_METADATA_PATH")
  fi
  if [[ -n "$SHORT_MAL_THRESHOLD" ]]; then
    args+=("--short-malicious-score-threshold" "$SHORT_MAL_THRESHOLD")
  fi
fi

exec "$PYTHON_BIN" src/ml_engine/model_interface.py "${args[@]}"
