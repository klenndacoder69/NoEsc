#!/bin/bash
set -euo pipefail

MAINT_FILE="/etc/noesc/sudo_maintenance_mode.until"

usage() {
  cat <<'EOF'
NoEsc maintenance mode helper

Usage:
  noesc-maint status
  noesc-maint off
  noesc-maint on <duration>
  noesc-maint until <epoch|date-string>

Examples:
  noesc-maint on 30m
  noesc-maint on 1h30m
  noesc-maint until 1767225600
  noesc-maint until "2026-03-30 23:30:00"
  noesc-maint off

Duration units:
  s = seconds, m = minutes, h = hours, d = days
EOF
}

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "[-] This command needs root privileges. Try: sudo noesc-maint ..."
    exit 1
  fi
}

parse_until_epoch() {
  local raw="$1"
  raw="${raw//[[:space:]]/}"
  if [[ -z "$raw" ]]; then
    echo ""
    return
  fi

  if [[ "$raw" == until_epoch=* ]]; then
    raw="${raw#until_epoch=}"
  fi

  if [[ "$raw" =~ ^[0-9]+$ ]]; then
    echo "$raw"
    return
  fi

  echo ""
}

parse_duration_seconds() {
  local input="$1"
  local rest="$input"
  local total=0

  while [[ -n "$rest" ]]; do
    if [[ "$rest" =~ ^([0-9]+)([smhd])(.*)$ ]]; then
      local n="${BASH_REMATCH[1]}"
      local unit="${BASH_REMATCH[2]}"
      rest="${BASH_REMATCH[3]}"

      case "$unit" in
      s) total=$((total + n)) ;;
      m) total=$((total + n * 60)) ;;
      h) total=$((total + n * 3600)) ;;
      d) total=$((total + n * 86400)) ;;
      esac
    else
      echo ""
      return
    fi
  done

  if [[ "$total" -le 0 ]]; then
    echo ""
    return
  fi

  echo "$total"
}

show_status() {
  local now
  now="$(date +%s)"

  if [[ ! -f "$MAINT_FILE" ]]; then
    echo "[NoEsc] Maintenance mode: INACTIVE"
    return
  fi

  local first_line
  first_line="$(head -n1 "$MAINT_FILE" 2>/dev/null || true)"
  local until
  until="$(parse_until_epoch "$first_line")"

  if [[ -z "$until" ]]; then
    echo "[NoEsc] Maintenance mode: INVALID FILE ($MAINT_FILE)"
    echo "         expected first line like: until_epoch=<unix_epoch>"
    return
  fi

  if (( until > now )); then
    local remaining
    remaining=$((until - now))
    echo "[NoEsc] Maintenance mode: ACTIVE"
    echo "         until_epoch=$until"
    echo "         until_human=$(date -d "@$until" '+%Y-%m-%d %H:%M:%S %Z')"
    echo "         remaining_seconds=$remaining"
  else
    echo "[NoEsc] Maintenance mode: EXPIRED"
    echo "         until_epoch=$until"
    echo "         until_human=$(date -d "@$until" '+%Y-%m-%d %H:%M:%S %Z')"
  fi
}

set_until_epoch() {
  local until="$1"
  require_root
  mkdir -p /etc/noesc
  printf 'until_epoch=%s\n' "$until" > "$MAINT_FILE"
  chmod 644 "$MAINT_FILE"
  echo "[NoEsc] Maintenance mode set until $(date -d "@$until" '+%Y-%m-%d %H:%M:%S %Z')"
}

cmd_off() {
  require_root
  rm -f "$MAINT_FILE"
  echo "[NoEsc] Maintenance mode disabled"
}

main() {
  local cmd="${1:-}"

  case "$cmd" in
  status)
    show_status
    ;;
  off)
    cmd_off
    ;;
  on)
    local duration="${2:-}"
    if [[ -z "$duration" ]]; then
      echo "[-] Missing duration"
      usage
      exit 1
    fi
    local secs
    secs="$(parse_duration_seconds "$duration")"
    if [[ -z "$secs" ]]; then
      echo "[-] Invalid duration: $duration"
      usage
      exit 1
    fi
    set_until_epoch "$(( $(date +%s) + secs ))"
    ;;
  until)
    local value="${2:-}"
    if [[ -z "$value" ]]; then
      echo "[-] Missing epoch/date value"
      usage
      exit 1
    fi
    local until
    if [[ "$value" =~ ^[0-9]+$ ]]; then
      until="$value"
    else
      if ! until="$(date -d "$value" +%s 2>/dev/null)"; then
        echo "[-] Invalid date string: $value"
        usage
        exit 1
      fi
    fi
    set_until_epoch "$until"
    ;;
  -h|--help|help|"")
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
