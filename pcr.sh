#!/bin/bash
#
# pcr.sh - TPM2 PCR Management Tool
#
# Standalone tool for PCR operations. Use this script:
#   - During production to set up PCR values
#   - At boot time on customer devices to restore PCR state
#   - For demo/testing to simulate boot cycles
#
# Usage:
#   ./pcr.sh extend <pcr> <value>    Extend PCR with SHA256 hash of value
#   ./pcr.sh reset <pcr>             Reset PCR to zero (PCR 16 only)
#   ./pcr.sh read [pcr]              Read PCR value(s)
#   ./pcr.sh boot                    Restore PCR from saved config (keys/pcr_value)
#
# Examples:
#   ./pcr.sh extend 16 "SERIAL-001"  # Extend PCR 16 with device serial
#   ./pcr.sh reset 16                # Reset PCR 16 (simulate reboot)
#   ./pcr.sh read 16                 # Show PCR 16 value
#   ./pcr.sh boot                    # Boot-time: restore from config
#
# PCR Notes:
#   PCR 0-15:  Hardware reset only (require actual reboot)
#   PCR 16:    Debug PCR, software resettable (for testing)
#   PCR 14-15: Recommended for production (bind to these)
#
# See PCR_POLICY.md for detailed documentation.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the library
source "$SCRIPT_DIR/tpm_lib.sh"

# =============================================================================
# Commands
# =============================================================================

cmd_extend() {
    local pcr="$1"
    local value="$2"

    if [ -z "$pcr" ] || [ -z "$value" ]; then
        echo "Usage: $0 extend <pcr> <value>"
        echo ""
        echo "Example: $0 extend 16 \"SERIAL-001\""
        exit 1
    fi

    pcr_extend "$pcr" "$value"
}

cmd_reset() {
    local pcr="$1"

    if [ -z "$pcr" ]; then
        echo "Usage: $0 reset <pcr>"
        echo ""
        echo "Note: Only PCR 16 can be reset by software."
        echo "      PCRs 0-15 require hardware reboot."
        exit 1
    fi

    pcr_reset "$pcr"
}

cmd_read() {
    local pcr="$1"

    if [ -z "$pcr" ]; then
        # Read common PCRs
        echo "PCR Values (SHA256):"
        echo "────────────────────────────────────────────────────────────────"
        for p in 0 1 2 7 14 15 16; do
            local val=$(tpm2_pcrread sha256:$p -o /dev/stdout 2>/dev/null | xxd -p | tr -d '\n')
            local zero=$(printf '0%.0s' {1..64})
            if [ "$val" = "$zero" ]; then
                printf "  PCR %2d: (zero)\n" "$p"
            else
                printf "  PCR %2d: %s...\n" "$p" "${val:0:32}"
            fi
        done
        echo ""
        echo "Use '$0 read <pcr>' for full value"
    else
        pcr_read "$pcr"
    fi
}

cmd_boot() {
    # Boot-time PCR restoration from saved config
    local pcr_file="${KEY_DIR}/pcr_policy"
    local value_file="${KEY_DIR}/pcr_value"

    if [ ! -f "$pcr_file" ] || [ ! -f "$value_file" ]; then
        echo "No PCR policy configured"
        echo "Files not found: $pcr_file, $value_file"
        exit 1
    fi

    local pcr=$(cat "$pcr_file")
    local value=$(cat "$value_file")

    echo "Boot-time PCR setup"
    echo "  PCR:   $pcr"
    echo "  Value: $value"
    echo ""

    # For PCR 16, we can reset first (demo mode)
    if [ "$pcr" = "16" ]; then
        echo "Resetting PCR 16..."
        pcr_reset 16
    fi

    # Extend with saved value
    pcr_extend "$pcr" "$value"
    echo ""
    echo "PCR $pcr ready for KeyVault"
}

show_usage() {
    echo "TPM2 PCR Management Tool"
    echo ""
    echo "Usage: $0 <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  extend <pcr> <value>  Extend PCR with SHA256 hash of value"
    echo "  reset <pcr>           Reset PCR to zero (PCR 16 only)"
    echo "  read [pcr]            Read PCR value(s)"
    echo "  boot                  Restore PCR from saved config (boot-time)"
    echo ""
    echo "Examples:"
    echo "  $0 extend 16 \"SERIAL-001\"    # Set device identity"
    echo "  $0 reset 16                   # Simulate reboot (demo)"
    echo "  $0 read                       # Show common PCR values"
    echo "  $0 boot                       # Boot-time restore"
    echo ""
    echo "PCR Information:"
    echo "  PCR 0-15:  Reset on hardware reboot only"
    echo "  PCR 16:    Debug PCR, software resettable"
    echo "  PCR 14-15: Recommended for production use"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

case "${1:-}" in
    extend)
        cmd_extend "$2" "$3"
        ;;
    reset)
        cmd_reset "$2"
        ;;
    read)
        cmd_read "$2"
        ;;
    boot)
        cmd_boot
        ;;
    -h|--help|help)
        show_usage
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
