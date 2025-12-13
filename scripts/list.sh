#!/bin/bash
#
# list.sh - List TPM2 Persistent Handles
#
# Quick tool to see what's stored in the TPM.
#
# Usage:
#   ./list.sh              List all persistent handles
#   ./list.sh --handle X   Set target handle marker
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Allow override of target handle
if [ "$1" = "--handle" ] && [ -n "$2" ]; then
    export TPM_HANDLE="$2"
fi

# Source the library
source "$SCRIPT_DIR/tpm_lib.sh"

echo ""
echo "TPM2 Persistent Storage"
echo "════════════════════════════════════════════════════════════════════"
echo ""

list_persistent_handles

echo ""
echo "Target handle: $TPM_HANDLE"
echo ""
