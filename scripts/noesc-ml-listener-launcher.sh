#!/bin/bash
set -euo pipefail

DEFAULT_PROJECT_ROOT="/opt/noesc"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

load_env_file() {
  local env_file="$1"
  if [[ -f "$env_file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  fi
}

# Allow development runs directly from repo scripts/ without requiring /etc env.
if [[ -z "${NOESC_PROJECT_ROOT:-}" ]]; then
  if [[ -f "$SCRIPT_DIR/../src/ml_engine/model_interface.py" ]]; then
    NOESC_PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
  fi
fi

# Machine-level deployment config (optional).
load_env_file "/etc/noesc/ml_listener.env"

PROJECT_ROOT="${NOESC_PROJECT_ROOT:-$DEFAULT_PROJECT_ROOT}"

# Project-level overrides (optional): lets deployment run from a repo .env file.
load_env_file "$PROJECT_ROOT/.env"
load_env_file "$PROJECT_ROOT/.env.local"
load_env_file "$PROJECT_ROOT/config/ml_listener.env"

PROJECT_ROOT="${NOESC_PROJECT_ROOT:-$PROJECT_ROOT}"
LISTENER_REL_PATH="src/ml_engine/model_interface.py"

if [[ ! -d "$PROJECT_ROOT" ]]; then
  echo "[-] NOESC_PROJECT_ROOT not found: $PROJECT_ROOT" >&2
  exit 1
fi

if [[ ! -f "$PROJECT_ROOT/$LISTENER_REL_PATH" ]]; then
  echo "[-] Listener entrypoint not found at: $PROJECT_ROOT/$LISTENER_REL_PATH" >&2
  echo "    Check NOESC_PROJECT_ROOT in /etc/noesc/ml_listener.env" >&2
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

exec "$PYTHON_BIN" "$LISTENER_REL_PATH" "${args[@]}"
