#!/bin/bash
set -euo pipefail

MODE_FILE="/etc/noesc/engine_mode"
DAEMON_BIN="/usr/local/bin/noesc_daemon"
WRAPPER_BIN="/usr/local/bin/noesc-daemon-wrapper"
ML_SERVICE="noesc-ml-listener"
ML_SOCKET_DEFAULT="/tmp/noesc_ml.sock"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

mark_pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "[PASS] $1"
}

mark_warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "[WARN] $1"
}

mark_fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "[FAIL] $1"
}

normalize_mode() {
  local mode_raw="${1:-}"
  local mode
  mode="$(printf '%s' "$mode_raw" | tr '[:upper:]' '[:lower:]' | xargs || true)"
  case "$mode" in
    hybrid|ml-only|ml_only|rules-only|rules_only)
      echo "$mode"
      ;;
    *)
      echo ""
      ;;
  esac
}

resolve_plugin_conf() {
  local candidates=(
    "/etc/audit/plugins.d/noesc.conf"
    "/etc/audisp/plugins.d/noesc.conf"
  )

  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      echo "$candidate"
      return
    fi
  done
  echo ""
}

extract_plugin_path() {
  local conf_path="$1"
  (sed -n -E 's/^[[:space:]]*path[[:space:]]*=[[:space:]]*(.*)$/\1/p' "$conf_path" | head -n1) || true
}

resolve_socket_path() {
  local env_file="/etc/noesc/ml_listener.env"
  if [[ -f "$env_file" ]]; then
    local value
    value="$( (rg -n '^NOESC_SOCKET_PATH=' "$env_file" 2>/dev/null | head -n1 | sed -E 's/^[^:]+:NOESC_SOCKET_PATH=//') || true )"
    if [[ -n "$value" ]]; then
      echo "$value"
      return
    fi
  fi
  echo "$ML_SOCKET_DEFAULT"
}

echo "[NoEsc] Health Check"
echo "--------------------"

if [[ -x "$DAEMON_BIN" ]]; then
  mark_pass "daemon binary present: $DAEMON_BIN"
else
  mark_fail "daemon binary missing or not executable: $DAEMON_BIN"
fi

if [[ -x "$WRAPPER_BIN" ]]; then
  mark_pass "wrapper binary present: $WRAPPER_BIN"
else
  mark_fail "wrapper binary missing or not executable: $WRAPPER_BIN"
fi

PLUGIN_CONF="$(resolve_plugin_conf)"
if [[ -z "$PLUGIN_CONF" ]]; then
  mark_fail "NoEsc plugin config not found in /etc/audit/plugins.d or /etc/audisp/plugins.d"
else
  mark_pass "plugin config found: $PLUGIN_CONF"
  if [[ ! -r "$PLUGIN_CONF" ]]; then
    mark_warn "plugin config is not readable; run with sudo for full validation"
  else
    PLUGIN_PATH="$(extract_plugin_path "$PLUGIN_CONF")"
    if [[ "$PLUGIN_PATH" == "$WRAPPER_BIN" ]]; then
      mark_pass "plugin path points to wrapper: $PLUGIN_PATH"
    elif [[ -n "$PLUGIN_PATH" ]]; then
      mark_fail "plugin path mismatch: $PLUGIN_PATH (expected $WRAPPER_BIN)"
    else
      mark_fail "plugin path not configured in $PLUGIN_CONF"
    fi
  fi
fi

# Detect conflicting dual plugin configs (common source of mode mismatch).
if [[ -f "/etc/audit/plugins.d/noesc.conf" && -f "/etc/audisp/plugins.d/noesc.conf" ]]; then
  AUDIT_PLUGIN_PATH="$(extract_plugin_path "/etc/audit/plugins.d/noesc.conf")"
  AUDISP_PLUGIN_PATH="$(extract_plugin_path "/etc/audisp/plugins.d/noesc.conf")"
  if [[ "$AUDIT_PLUGIN_PATH" != "$AUDISP_PLUGIN_PATH" ]]; then
    mark_fail "conflicting plugin paths: /etc/audit/plugins.d/noesc.conf -> $AUDIT_PLUGIN_PATH, /etc/audisp/plugins.d/noesc.conf -> $AUDISP_PLUGIN_PATH"
  elif [[ "$AUDIT_PLUGIN_PATH" == "$WRAPPER_BIN" ]]; then
    mark_pass "dual plugin configs are consistent"
  fi
fi

MODE_VALUE=""
if [[ -f "$MODE_FILE" ]]; then
  MODE_VALUE="$(normalize_mode "$(head -n1 "$MODE_FILE" 2>/dev/null || true)")"
  if [[ -n "$MODE_VALUE" ]]; then
    mark_pass "engine mode file set: $MODE_VALUE"
  else
    mark_warn "engine mode file has invalid value; default behavior is hybrid"
  fi
else
  mark_warn "engine mode file missing; default behavior is hybrid"
fi

collect_daemon_lines() {
  # Health should validate the deployed daemon instance, not ad-hoc local
  # test runs (e.g. ./noesc_daemon --rules-only from a shell).
  pgrep -af "^${DAEMON_BIN}($| )" || true
}

DAEMON_LINES="$(collect_daemon_lines)"
if [[ -n "$DAEMON_LINES" ]]; then
  DAEMON_COUNT="$(printf '%s\n' "$DAEMON_LINES" | rg -c "^" || true)"
else
  DAEMON_COUNT="0"
fi
if [[ "$DAEMON_COUNT" == "1" ]]; then
  mark_pass "single daemon process running"
  echo "       $(printf '%s' "$DAEMON_LINES")"
elif [[ "$DAEMON_COUNT" == "0" ]]; then
  mark_fail "no daemon process running"
else
  mark_fail "multiple daemon processes detected ($DAEMON_COUNT)"
  printf '%s\n' "$DAEMON_LINES" | sed 's/^/       /'
fi

if [[ "${DAEMON_COUNT:-0}" -ge 1 ]]; then
  case "$MODE_VALUE" in
    ml-only|ml_only)
      if printf '%s\n' "$DAEMON_LINES" | rg -- '--ml-only' >/dev/null; then
        mark_pass "runtime args match mode (ml-only)"
      else
        mark_fail "runtime args do not include --ml-only"
      fi
      ;;
    rules-only|rules_only)
      if printf '%s\n' "$DAEMON_LINES" | rg -- '--rules-only' >/dev/null; then
        mark_pass "runtime args match mode (rules-only)"
      else
        mark_fail "runtime args do not include --rules-only"
      fi
      ;;
    hybrid|"")
      if printf '%s\n' "$DAEMON_LINES" | rg -- '--ml-only|--rules-only' >/dev/null; then
        mark_fail "runtime args indicate non-hybrid mode while config is hybrid/default"
      else
        mark_pass "runtime args match mode (hybrid/default)"
      fi
      ;;
  esac
fi

if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet "$ML_SERVICE" 2>/dev/null; then
    mark_pass "ML listener service active: $ML_SERVICE"
  elif systemctl status "$ML_SERVICE" >/dev/null 2>&1; then
    mark_fail "ML listener service inactive: $ML_SERVICE"
  else
    mark_warn "systemd not reachable from current shell; skipped ML service state check"
  fi
else
  mark_warn "systemctl not found; skipped ML service check"
fi

SOCKET_PATH="$(resolve_socket_path)"
if [[ -S "$SOCKET_PATH" ]]; then
  mark_pass "ML socket present: $SOCKET_PATH"
else
  mark_fail "ML socket missing: $SOCKET_PATH"
fi

if command -v ss >/dev/null 2>&1; then
  if ss -xl 2>/dev/null | rg -F "$SOCKET_PATH" >/dev/null; then
    mark_pass "ML socket visible in kernel socket table"
  else
    mark_fail "ML socket not present in kernel socket table"
  fi
else
  mark_warn "ss command not found; skipped kernel socket table check"
fi

echo "--------------------"
echo "[NoEsc] Results: pass=$PASS_COUNT warn=$WARN_COUNT fail=$FAIL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi

exit 0
