#!/bin/bash

# NoEsc lab setup: plant one randomized SUID backdoor binary for Vector 1.

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./setup_lab_vulns.sh)"
  exit 1
fi

set -u

DEST_DIRS=("/tmp" "/var/tmp" "/dev/shm")
PAYLOADS=("/bin/bash" "/usr/bin/find")
NAMES=(
  ".cache-monitor"
  ".dbus-session-helper"
  ".systemd-user-agent"
  ".font-cache-update"
  ".pipewire-helper"
)

is_suid_exec_capable_mount() {
  local dir="$1"
  local opts

  if ! command -v findmnt > /dev/null 2>&1; then
    return 0
  fi

  opts="$(findmnt -T "$dir" -no OPTIONS 2>/dev/null || true)"
  if [ -z "$opts" ]; then
    return 0
  fi

  case ",$opts," in
    *,nosuid,*|*,noexec,*)
      return 1
      ;;
  esac

  return 0
}

SUPPORTED_DEST_DIRS=()
for dir in "${DEST_DIRS[@]}"; do
  if is_suid_exec_capable_mount "$dir"; then
    SUPPORTED_DEST_DIRS+=("$dir")
  else
    echo "[!] Skipping $dir for SUID payload (mount has nosuid/noexec)"
  fi
done

if [ "${#SUPPORTED_DEST_DIRS[@]}" -eq 0 ]; then
  echo "[-] No writable destination supports SUID execution (/tmp, /var/tmp, /dev/shm all filtered)."
  exit 1
fi

dest_dir="${SUPPORTED_DEST_DIRS[$RANDOM % ${#SUPPORTED_DEST_DIRS[@]}]}"
payload_src="${PAYLOADS[$RANDOM % ${#PAYLOADS[@]}]}"
payload_name="${NAMES[$RANDOM % ${#NAMES[@]}]}"
payload_path="${dest_dir}/${payload_name}"

echo "[*] Planting randomized SUID payload..."
cp "$payload_src" "$payload_path"
chown root:root "$payload_path"
chmod 4755 "$payload_path"

echo "$payload_path" > /tmp/.vuln_path
chmod 644 /tmp/.vuln_path

if [ "$payload_src" = "/bin/bash" ]; then
  echo "bash" > /tmp/.vuln_kind
else
  echo "find" > /tmp/.vuln_kind
fi
chmod 644 /tmp/.vuln_kind

echo "[+] Vector 1 ready"
echo "    Source:      $payload_src"
echo "    Planted as:  $payload_path"
echo "    Path marker: /tmp/.vuln_path"
