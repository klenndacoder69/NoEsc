#!/bin/bash
set -euo pipefail

DAEMON_BIN="/usr/local/bin/noesc_daemon"
MODE_FILE="/etc/noesc/engine_mode"

if [[ ! -x "$DAEMON_BIN" ]]; then
  echo "[-] Missing daemon binary: $DAEMON_BIN" >&2
  exit 1
fi

# Display-manager / system accounts must never be used for GUI notifications
# (they often look "active" during lock / login transitions).
is_bad_notify_user() {
  local u="${1:-}"
  [[ -z "$u" || "$u" == "root" ]] && return 0
  case "$u" in
    gdm|lightdm|sddm|kdm|lxdm|display-manager) return 0 ;;
  esac
  [[ "$u" == _* ]] && return 0
  return 1
}

resolve_notify_user() {
  # 1) Explicit operator override (e.g. /etc/noesc/notify_user); must not be a DM account.
  if [[ -n "${NOESC_NOTIFY_USER:-}" ]] && ! is_bad_notify_user "$NOESC_NOTIFY_USER"; then
    printf '%s\n' "$NOESC_NOTIFY_USER"
    return 0
  fi

  # 1b) Persistent one-line config (survives auditd spawn with no env)
  local conf_user
  conf_user="$(tr -d '\r\n' < /etc/noesc/notify_user 2>/dev/null | xargs || true)"
  if [[ -n "$conf_user" ]] && ! is_bad_notify_user "$conf_user"; then
    printf '%s\n' "$conf_user"
    return 0
  fi

  # 2) Sudo flow for manual foreground runs.
  if [[ -n "${SUDO_USER:-}" ]] && ! is_bad_notify_user "$SUDO_USER"; then
    printf '%s\n' "$SUDO_USER"
    return 0
  fi

  # 3) Active graphical session (prefer wayland/x11 so we skip stray "active" sessions).
  if command -v loginctl >/dev/null 2>&1; then
    local sid session_user sess_type
    while read -r sid; do
      [[ -z "$sid" ]] && continue
      [[ "$(loginctl show-session "$sid" -p Active --value 2>/dev/null || true)" != "yes" ]] && continue
      session_user="$(loginctl show-session "$sid" -p Name --value 2>/dev/null || true)"
      is_bad_notify_user "$session_user" && continue
      sess_type="$(loginctl show-session "$sid" -p Type --value 2>/dev/null || true)"
      case "$sess_type" in
        wayland|x11)
          printf '%s\n' "$session_user"
          return 0
          ;;
      esac
    done < <(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}')

    while read -r sid; do
      [[ -z "$sid" ]] && continue
      [[ "$(loginctl show-session "$sid" -p Active --value 2>/dev/null || true)" != "yes" ]] && continue
      session_user="$(loginctl show-session "$sid" -p Name --value 2>/dev/null || true)"
      if [[ -n "$session_user" ]] && ! is_bad_notify_user "$session_user"; then
        printf '%s\n' "$session_user"
        return 0
      fi
    done < <(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}')
  fi

  # 4) who(1) fallback
  local who_user
  who_user="$(who | awk '/\(:/ {print $1; exit}')"
  if [[ -n "$who_user" ]] && ! is_bad_notify_user "$who_user"; then
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
