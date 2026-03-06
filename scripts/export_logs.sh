#!/bin/bash

# NoEsc Log Export Helper
# Usage: sudo ./export_logs.sh [username]

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./scripts/export_logs.sh)"
  exit 1
fi

# Detect user (either passed as arg or derived from SUDO_USER)
TARGET_USER=${1:-$SUDO_USER}

if [ -z "$TARGET_USER" ]; then
  echo "[-] Could not detect user. Usage: sudo ./export_logs.sh <username>"
  exit 1
fi

EXPORT_DIR="/home/$TARGET_USER/Desktop"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ARCHIVE_NAME="noesc_audit_logs_$TIMESTAMP.tar.gz"
OUTPUT_PATH="$EXPORT_DIR/$ARCHIVE_NAME"

echo "[*] Exporting logs for user: $TARGET_USER"
echo "[*] Destination: $OUTPUT_PATH"

mkdir -p "$EXPORT_DIR"

# Create the archive (preserving original filenames but copying content)
# We use tar to bundle them up
tar -czf "$OUTPUT_PATH" /var/log/audit/audit.log* 2

if [ $? -eq 0 ]; then
  # CRITICAL: Change ownership so the normal user can touch it
  chown "$TARGET_USER:$TARGET_USER" "$OUTPUT_PATH"
  chmod 644 "$OUTPUT_PATH"

  echo "[+] Success! You can now drag '$ARCHIVE_NAME' to Google Drive."
else
  echo "[-] Failed to create archive."
fi
