#!/usr/bin/env bash
# ==============================================================================
# VaultSync — Chromium & Chrome Native Messaging Host Unregistration Script
#
# Removes com.vaultsync.native host manifests safely from per-user or system paths.
# Only removes manifests verified to belong to VaultSync.
# ==============================================================================

set -euo pipefail 2>/dev/null || set -eu

HOST_NAME="com.vaultsync.native"
MANIFEST_FILENAME="${HOST_NAME}.json"

MODE="user"
TARGET_BROWSER="all"

print_usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Unregisters the VaultSync Native Messaging Host manifest for Chromium and Google Chrome.

Options:
  -s, --system           Remove system-wide registrations from /etc (requires root/sudo)
  -u, --user             Remove per-user registrations from ~/.config (default)
      --browser BROWSER  Target browser: 'chromium', 'chrome', or 'all' (default: 'all')
  -h, --help             Show this help message and exit

Examples:
  # Remove per-user registration
  $(basename "$0")

  # Remove system-wide registration (as root)
  sudo $(basename "$0") --system
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--system)
            MODE="system"
            shift
            ;;
        -u|--user)
            MODE="user"
            shift
            ;;
        --browser)
            TARGET_BROWSER="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option '$1'" >&2
            print_usage >&2
            exit 1
            ;;
    esac
done

TARGET_DIRS=()
CONFIG_BASE="${XDG_CONFIG_HOME:-$HOME/.config}"

if [[ "${MODE}" == "system" ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "Error: System-wide unregistration requires root privileges (run with sudo)." >&2
        exit 1
    fi
    case "${TARGET_BROWSER}" in
        chromium)
            TARGET_DIRS=("/etc/chromium/native-messaging-hosts")
            ;;
        chrome)
            TARGET_DIRS=("/etc/opt/chrome/native-messaging-hosts")
            ;;
        all)
            TARGET_DIRS=(
                "/etc/chromium/native-messaging-hosts"
                "/etc/opt/chrome/native-messaging-hosts"
            )
            ;;
        *)
            echo "Error: Invalid browser '${TARGET_BROWSER}'. Use 'chromium', 'chrome', or 'all'." >&2
            exit 1
            ;;
    esac
else
    case "${TARGET_BROWSER}" in
        chromium)
            TARGET_DIRS=("${CONFIG_BASE}/chromium/NativeMessagingHosts")
            ;;
        chrome)
            TARGET_DIRS=("${CONFIG_BASE}/google-chrome/NativeMessagingHosts")
            ;;
        all)
            TARGET_DIRS=(
                "${CONFIG_BASE}/chromium/NativeMessagingHosts"
                "${CONFIG_BASE}/google-chrome/NativeMessagingHosts"
            )
            ;;
        *)
            echo "Error: Invalid browser '${TARGET_BROWSER}'. Use 'chromium', 'chrome', or 'all'." >&2
            exit 1
            ;;
    esac
fi

REMOVED_COUNT=0

for dir in "${TARGET_DIRS[@]}"; do
    target_file="${dir}/${MANIFEST_FILENAME}"

    if [[ -f "${target_file}" ]]; then
        # Safety check: ensure file belongs to VaultSync before removing
        if grep -q "\"${HOST_NAME}\"" "${target_file}" 2>/dev/null; then
            rm -f "${target_file}"
            echo "  ✓ Removed: ${target_file}"
            REMOVED_COUNT=$((REMOVED_COUNT + 1))
        else
            echo "  ! Skipping '${target_file}': does not match VaultSync host name '${HOST_NAME}'." >&2
        fi
    fi
done

if [[ "${REMOVED_COUNT}" -gt 0 ]]; then
    echo "==> Unregistered VaultSync host '${HOST_NAME}' from ${REMOVED_COUNT} location(s)."
else
    echo "==> No active VaultSync manifests found in the specified location(s)."
fi
