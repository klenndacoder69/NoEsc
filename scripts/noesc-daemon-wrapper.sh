#!/bin/bash
set -euo pipefail

DAEMON_BIN="/usr/local/bin/noesc_daemon"
MODE_FILE="/etc/noesc/engine_mode"

if [[ ! -x "$DAEMON_BIN" ]]; then
  echo "[-] Missing daemon binary: $DAEMON_BIN" >&2
  exit 1
fi

trimmed_mode="${NOESC_ENGINE_MODE:-}"
if [[ -z "$trimmed_mode" && -f "$MODE_FILE" ]]; then
  trimmed_mode="$(head -n1 "$MODE_FILE" 2>/dev/null || true)"
fi

trimmed_mode="$(printf '%s' "$trimmed_mode" | tr '[:upper:]' '[:lower:]' | xargs || true)"

case "$trimmed_mode" in
  ""|hybrid)
    exec "$DAEMON_BIN" "$@"
    ;;
  ml-only|ml_only)
    exec "$DAEMON_BIN" --ml-only "$@"
    ;;
  rules-only|rules_only)
    exec "$DAEMON_BIN" --rules-only "$@"
    ;;
  *)
    echo "[!] Unknown engine mode '$trimmed_mode'; defaulting to hybrid" >&2
    exec "$DAEMON_BIN" "$@"
    ;;
esac
