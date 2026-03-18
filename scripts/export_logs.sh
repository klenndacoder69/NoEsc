#!/bin/bash

# NoEsc Log Export Helper
# Usage: sudo ./export_logs.sh [pc_identifier]
# Example: sudo ./export_logs.sh pc1

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./scripts/export_logs.sh)"
  exit 1
fi

# Get PC identifier from argument (optional but recommended)
PC_ID=${1:-"unknown"}

# Detect user from SUDO_USER
TARGET_USER=${SUDO_USER}

if [ -z "$TARGET_USER" ]; then
  echo "[-] Could not detect user. Please run with sudo."
  exit 1
fi

EXPORT_DIR="/home/$TARGET_USER/Desktop"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ARCHIVE_NAME="noesc_audit_logs_${PC_ID}_${TIMESTAMP}.tar.gz"
OUTPUT_PATH="$EXPORT_DIR/$ARCHIVE_NAME"

echo "[*] PC Identifier: $PC_ID"
echo "[*] Exporting logs for user: $TARGET_USER"
echo "[*] Destination: $OUTPUT_PATH"

mkdir -p "$EXPORT_DIR"

# Create the archive (preserving original filenames but copying content)
# We use tar to bundle them up
# Using --ignore-failed-read to handle active log files
tar --ignore-failed-read -czf "$OUTPUT_PATH" /var/log/audit/audit.log* 2>&1 | grep -v "Removing leading" | grep -v "file changed as we read it" | grep -v "^$" || true

if [ $? -eq 0 ] && [ -f "$OUTPUT_PATH" ]; then
  # CRITICAL: Change ownership so the normal user can touch it
  chown "$TARGET_USER:$TARGET_USER" "$OUTPUT_PATH"
  chmod 644 "$OUTPUT_PATH"

  # Show archive size for user awareness
  ARCHIVE_SIZE=$(du -h "$OUTPUT_PATH" | cut -f1)
  echo "[+] Success! Archive created: $ARCHIVE_SIZE"
  echo "[+] You can now drag '$ARCHIVE_NAME' to Google Drive."
else
  echo "[-] Failed to create archive."
  exit 1
fi
