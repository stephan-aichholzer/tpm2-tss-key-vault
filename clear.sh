#!/bin/bash
#
# clear.sh - Remove KeyVault Key from TPM
#
# Removes the KeyVault key and associated files.
#
# Usage:
#   ./clear.sh                 Remove key at default handle (0x81010002)
#   ./clear.sh --handle 0x...  Remove key at specific handle
#   ./clear.sh --force         Skip safety checks
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
FORCE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --handle)
            export TPM_HANDLE="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--handle 0x...] [--force]"
            echo ""
            echo "Options:"
            echo "  --handle 0x...  Handle to clear (default: 0x81010002)"
            echo "  --force         Skip safety checks"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Source the library
source "$SCRIPT_DIR/tpm_lib.sh"

echo ""
echo "TPM2 KeyVault Key Removal"
echo "════════════════════════════════════════════════════════════════════"
echo ""

# Check if key exists
if ! tpm2_readpublic -c "$TPM_HANDLE" &> /dev/null; then
    echo "No key found at $TPM_HANDLE"
    exit 1
fi

# Safety check
if [ "$FORCE" != "true" ]; then
    if ! is_keyvault_key "$TPM_HANDLE"; then
        echo "  ┌─────────────────────────────────────────────────────────────┐"
        echo "  │  WARNING: Key at $TPM_HANDLE doesn't look like KeyVault!    │"
        echo "  │                                                             │"
        echo "  │  This may belong to another application.                    │"
        echo "  │  Use --force if you're SURE you want to remove it.          │"
        echo "  └─────────────────────────────────────────────────────────────┘"
        exit 2
    fi
fi

# Remove the key
echo "Removing key at $TPM_HANDLE..."
if remove_key "$TPM_HANDLE"; then
    echo "Key removed from TPM"
else
    echo "ERROR: Failed to remove key"
    exit 1
fi

# Clean up local files
echo ""
echo "Cleaning up files..."

for f in "$PUBLIC_KEY_PEM" "$EK_CTX" "$EK_PUB" "$PCR_POLICY_FILE" "$PCR_VALUE_FILE"; do
    if [ -f "$f" ]; then
        rm -f "$f"
        echo "  Removed: $f"
    fi
done

echo ""
echo "KeyVault cleared. Run ./init.sh to re-provision."
echo ""
