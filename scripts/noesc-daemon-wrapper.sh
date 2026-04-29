#!/bin/bash
set -euo pipefail

DAEMON_BIN="/usr/local/bin/noesc_daemon"
MODE_FILE="/etc/noesc/engine_mode"

if [[ ! -x "$DAEMON_BIN" ]]; then
  echo "[-] Missing daemon binary: $DAEMON_BIN" >&2
  exit 1
fi

resolve_notify_user() {
  # 1) Explicit operator override always wins.
  if [[ -n "${NOESC_NOTIFY_USER:-}" ]]; then
    printf '%s\n' "$NOESC_NOTIFY_USER"
    return 0
  fi

  # 2) Keep sudo flow compatibility for manual foreground runs.
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    printf '%s\n' "$SUDO_USER"
    return 0
  fi

  # 3) Prefer the active graphical session user when systemd/logind is present.
  if command -v loginctl >/dev/null 2>&1; then
    while IFS= read -r session_id; do
      [[ -z "$session_id" ]] && continue
      if [[ "$(loginctl show-session "$session_id" -p Active --value 2>/dev/null || true)" != "yes" ]]; then
        continue
      fi
      local session_user
      session_user="$(loginctl show-session "$session_id" -p Name --value 2>/dev/null || true)"
      if [[ -n "$session_user" && "$session_user" != "root" ]]; then
        printf '%s\n' "$session_user"
        return 0
      fi
    done < <(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}')
  fi

  # 4) Fallback for non-logind setups.
  local who_user
  who_user="$(who | awk '/\(:/ {print $1; exit}')"
  if [[ -n "$who_user" && "$who_user" != "root" ]]; then
    printf '%s\n' "$who_user"
    return 0
  fi

  return 1
}

if resolved_notify_user="$(resolve_notify_user)"; then
  export NOESC_NOTIFY_USER="$resolved_notify_user"
fi

# In deployed auditd mode, /etc/noesc/engine_mode is the source of truth.
# NOESC_ENGINE_MODE is only a fallback for ad-hoc/manual launches.
trimmed_mode=""
if [[ -f "$MODE_FILE" ]]; then
  trimmed_mode="$(head -n1 "$MODE_FILE" 2>/dev/null || true)"
fi
if [[ -z "$trimmed_mode" ]]; then
  trimmed_mode="${NOESC_ENGINE_MODE:-}"
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
