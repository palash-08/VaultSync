#!/usr/bin/env bash
# ==============================================================================
# VaultSync — Chromium & Chrome Native Messaging Host Registration Script
#
# Registers the com.vaultsync.native host manifest for Chromium and Google Chrome
# in per-user ($HOME/.config/...) or system-wide (/etc/...) directories.
# ==============================================================================

set-euo pipefail 2>/dev/null || set -eu

HOST_NAME="com.vaultsync.native"
EXTENSION_ID="fhmcpggbfoaaglijeknjdnpnehbpdajb"
ALLOWED_ORIGIN="chrome-extension://${EXTENSION_ID}/"
DESCRIPTION="VaultSync Native Messaging Host"
MANIFEST_FILENAME="${HOST_NAME}.json"

MODE="user"
TARGET_BROWSER="all"
EXPLICIT_BINARY=""

print_usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Registers the VaultSync Native Messaging Host manifest for Chromium and Google Chrome.

Options:
  -b, --binary PATH      Explicit absolute or relative path to vaultsync-host executable
  -s, --system           Install system-wide into /etc (requires root/sudo)
  -u, --user             Install for current user only into ~/.config (default)
      --browser BROWSER  Target browser: 'chromium', 'chrome', or 'all' (default: 'all')
  -h, --help             Show this help message and exit

Examples:
  # Register local development build for current user
  $(basename "$0") --binary ./build/vaultsync-host

  # Auto-detect installed binary and register per-user
  $(basename "$0")

  # Register system-wide (as root)
  sudo $(basename "$0") --system --binary /usr/bin/vaultsync-host
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--binary)
            EXPLICIT_BINARY="$2"
            shift 2
            ;;
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

# Locate vaultsync-host executable
RESOLVED_BINARY=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${EXPLICIT_BINARY}" ]]; then
    if [[ -f "${EXPLICIT_BINARY}" && -x "${EXPLICIT_BINARY}" ]]; then
        RESOLVED_BINARY="$(readlink -f "${EXPLICIT_BINARY}" 2>/dev/null || realpath "${EXPLICIT_BINARY}")"
    else
        echo "Error: Specified binary '${EXPLICIT_BINARY}' does not exist or is not executable." >&2
        exit 1
    fi
else
    # Auto-detection sequence
    CANDIDATES=(
        "${SCRIPT_DIR}/../build/vaultsync-host"
        "/usr/bin/vaultsync-host"
        "/usr/local/bin/vaultsync-host"
        "${HOME}/.local/bin/vaultsync-host"
    )
    if command -v vaultsync-host >/dev/null 2>&1; then
        CANDIDATES=("$(command -v vaultsync-host)" "${CANDIDATES[@]}")
    fi

    for cand in "${CANDIDATES[@]}"; do
        if [[ -f "${cand}" && -x "${cand}" ]]; then
            RESOLVED_BINARY="$(readlink -f "${cand}" 2>/dev/null || realpath "${cand}")"
            break
        fi
    done
fi

if [[ -z "${RESOLVED_BINARY}" ]]; then
    echo "Error: vaultsync-host executable could not be found." >&2
    echo "Please build the project first ('cmake --build build --target vaultsync-host') or specify '--binary PATH'." >&2
    exit 1
fi

echo "==> Using executable: ${RESOLVED_BINARY}"

# Determine target manifest directories
TARGET_DIRS=()
CONFIG_BASE="${XDG_CONFIG_HOME:-$HOME/.config}"

if [[ "${MODE}" == "system" ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "Error: System-wide registration requires root privileges (run with sudo)." >&2
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

# Manifest JSON generator
generate_manifest_json() {
    local bin_path="$1"
    cat <<EOF
{
  "name": "${HOST_NAME}",
  "description": "${DESCRIPTION}",
  "path": "${bin_path}",
  "type": "stdio",
  "allowed_origins": [
    "${ALLOWED_ORIGIN}"
  ]
}
EOF
}

# Install manifest into each target directory
SUCCESS_COUNT=0
for dir in "${TARGET_DIRS[@]}"; do
    if [[ ! -d "${dir}" ]]; then
        mkdir -p "${dir}"
        if [[ "${MODE}" == "user" ]]; then
            chmod 700 "${dir}" 2>/dev/null || true
        else
            chmod 755 "${dir}" 2>/dev/null || true
        fi
    fi

    target_file="${dir}/${MANIFEST_FILENAME}"

    # Safety check: if target file exists and is not a VaultSync host manifest, warn and back it up
    if [[ -f "${target_file}" ]]; then
        if ! grep -q "\"${HOST_NAME}\"" "${target_file}" 2>/dev/null; then
            echo "Warning: Existing file at '${target_file}' is not a VaultSync manifest. Backing up to '${target_file}.bak'..." >&2
            cp -p "${target_file}" "${target_file}.bak"
        fi
    fi

    # Write atomically via temp file
    temp_file="${dir}/.${MANIFEST_FILENAME}.tmp.$$"
    generate_manifest_json "${RESOLVED_BINARY}" > "${temp_file}"

    # Validate JSON syntax with python3 if available
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 -m json.tool "${temp_file}" >/dev/null 2>&1; then
            echo "Error: Generated manifest failed JSON syntax validation." >&2
            rm -f "${temp_file}"
            exit 1
        fi
    fi

    chmod 644 "${temp_file}"
    mv -f "${temp_file}" "${target_file}"

    echo "  ✓ Registered manifest at: ${target_file}"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
done

echo "==> Successfully registered VaultSync host '${HOST_NAME}' in ${SUCCESS_COUNT} location(s)."
echo "    Allowed Origin: ${ALLOWED_ORIGIN}"
