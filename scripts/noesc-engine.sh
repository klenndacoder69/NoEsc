#!/bin/bash
set -euo pipefail

MODE_FILE="/etc/noesc/engine_mode"
PLUGIN_CONF="/etc/audit/plugins.d/noesc.conf"
DAEMON_BIN="/usr/local/bin/noesc_daemon"

usage() {
  cat <<'EOF'
NoEsc engine mode switcher

Usage:
  noesc-engine status
  noesc-engine set <hybrid|ml-only|rules-only>
  noesc-engine hybrid
  noesc-engine ml-only
  noesc-engine rules-only
  noesc-engine reload

Notes:
- This controls the deployed audisp daemon mode via /etc/noesc/engine_mode.
- Run 'noesc-engine reload' (or set) to apply immediately.
EOF
}

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "[-] This command needs root privileges. Try: sudo noesc-engine ..."
    exit 1
  fi
}

normalize_mode() {
  local mode_raw="${1:-}"
  local mode
  mode="$(printf '%s' "$mode_raw" | tr '[:upper:]' '[:lower:]' | xargs || true)"
  case "$mode" in
    hybrid)
      echo "hybrid"
      ;;
    ml-only|ml_only)
      echo "ml-only"
      ;;
    rules-only|rules_only)
      echo "rules-only"
      ;;
    *)
      echo ""
      ;;
  esac
}

current_mode() {
  if [[ -f "$MODE_FILE" ]]; then
    normalize_mode "$(head -n1 "$MODE_FILE" 2>/dev/null || true)"
  else
    echo ""
  fi
}

reload_auditd() {
  require_root
  # Ensure mode changes apply immediately by removing stale daemon instances.
  # auditd will respawn the plugin process with the latest wrapper-selected flags.
  pkill -f "^${DAEMON_BIN}($| )" >/dev/null 2>&1 || true

  if pgrep -x auditd >/dev/null 2>&1; then
    pkill -HUP auditd || kill -s SIGHUP "$(pidof auditd)"
    echo "[+] auditd reloaded"
  else
    echo "[!] auditd is not running"
    return 1
  fi
}

set_mode() {
  require_root
  local mode
  mode="$(normalize_mode "${1:-}")"
  if [[ -z "$mode" ]]; then
    echo "[-] Invalid mode. Use: hybrid, ml-only, rules-only"
    exit 1
  fi

  mkdir -p /etc/noesc
  printf '%s\n' "$mode" > "$MODE_FILE"
  chmod 644 "$MODE_FILE"
  echo "[+] Set engine mode: $mode"

  reload_auditd
}

show_status() {
  local mode
  mode="$(current_mode)"
  if [[ -z "$mode" ]]; then
    mode="hybrid (default)"
  fi

  echo "[NoEsc] Engine mode file: $MODE_FILE"
  echo "[NoEsc] Active configured mode: $mode"

  if [[ -f "$PLUGIN_CONF" ]]; then
    echo "[NoEsc] Plugin path: $(grep -E '^path\s*=' "$PLUGIN_CONF" | head -n1 | sed 's/^path\s*=\s*//')"
  else
    echo "[NoEsc] Plugin config not found at $PLUGIN_CONF"
  fi
}

main() {
  local cmd="${1:-status}"
  case "$cmd" in
    status)
      show_status
      ;;
    set)
      set_mode "${2:-}"
      ;;
    hybrid|ml-only|rules-only|ml_only|rules_only)
      set_mode "$cmd"
      ;;
    reload)
      reload_auditd
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      echo "[-] Unknown command: $cmd"
      usage
      exit 1
      ;;
  esac
}

main "$@"
