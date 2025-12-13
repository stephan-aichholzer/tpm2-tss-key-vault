#!/bin/bash
#
# init.sh - TPM2 Key Provisioning Script
#
# This script initializes the TPM2 for use with the KeyVault system.
# Run this ONCE during factory provisioning or initial device setup.
#
# What this script does:
#   1. Creates Endorsement Key context (for encrypted sessions)
#   2. Creates a primary storage key in the TPM
#   3. Creates an RSA-2048 key for encrypt/decrypt/sign operations
#   4. Optionally binds the key to a PCR policy (hardware identity)
#   5. Persists the key at handle 0x81010002
#   6. Exports the public key as PEM for use by applications
#
# Prerequisites:
#   - TPM2 device accessible (/dev/tpm0 or /dev/tpmrm0)
#   - User in 'tss' group (or root)
#   - tpm2-tools package installed
#
# Usage:
#   ./init.sh                                    # Normal initialization
#   ./init.sh --pcr 16 --pcr-value "SERIAL"     # With PCR policy binding
#   ./init.sh --force                            # Remove existing key and recreate
#   ./init.sh --check                            # Check if key already exists
#   ./init.sh --handle 0x81010003                # Use a specific handle
#
# Related tools:
#   ./list.sh           List all persistent handles
#   ./clear.sh          Remove KeyVault key from TPM
#   ./pcr.sh            PCR management (extend, reset, read)
#
# Security Note:
#   The private key is generated INSIDE the TPM and NEVER leaves the chip.
#   Only the public key is exported to the filesystem.
#
# See Also:
#   - PCR_POLICY.md for PCR binding documentation
#   - INIT.md for detailed initialization explanation
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the library
source "$SCRIPT_DIR/tpm_lib.sh"

# Set up cleanup trap
trap tpm_cleanup EXIT

# =============================================================================
# Argument Parsing
# =============================================================================

FORCE=false
CHECK_ONLY=false
PCR_NUM=""
PCR_VALUE=""

show_usage() {
    echo "TPM2 Key Provisioning Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --check              Check if key exists (exit 0 if yes, 1 if no)"
    echo "  --force              Force operation (overwrite existing key)"
    echo "  --handle 0x810100XX  Use a specific handle (default: $DEFAULT_HANDLE)"
    echo "  --pcr <14|15|16>     Bind key to PCR policy"
    echo "  --pcr-value <value>  Identity value for PCR (required with --pcr)"
    echo "  --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Basic provisioning"
    echo "  $0 --pcr 16 --pcr-value \"SERIAL-001\" # With PCR binding (demo)"
    echo "  $0 --pcr 14 --pcr-value \"SERIAL-001\" # With PCR binding (production)"
    echo "  $0 --force                            # Re-provision existing key"
    echo ""
    echo "Related tools:"
    echo "  ./list.sh      List TPM persistent handles"
    echo "  ./clear.sh     Remove KeyVault key"
    echo "  ./pcr.sh       PCR management (extend/reset/read)"
    echo ""
    echo "PCR Notes:"
    echo "  PCR 16: Debug PCR, software resettable (for testing)"
    echo "  PCR 14-15: Production PCRs, reset on reboot only"
    echo ""
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE=true
            shift
            ;;
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --handle)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "ERROR: --handle requires a value (e.g., --handle 0x81010003)"
                exit 1
            fi
            if [[ ! "$2" =~ ^0x81[0-9a-fA-F]{6}$ ]]; then
                echo "ERROR: Invalid handle format: $2"
                echo "       Expected format: 0x81XXXXXX (e.g., 0x81010002)"
                exit 1
            fi
            TPM_HANDLE="$2"
            shift 2
            ;;
        --pcr)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "ERROR: --pcr requires a value (14, 15, or 16)"
                exit 1
            fi
            if [[ ! "$2" =~ ^(14|15|16)$ ]]; then
                echo "ERROR: --pcr must be 14, 15, or 16"
                exit 1
            fi
            PCR_NUM="$2"
            shift 2
            ;;
        --pcr-value)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "ERROR: --pcr-value requires a value"
                exit 1
            fi
            PCR_VALUE="$2"
            shift 2
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate PCR arguments
if [ -n "$PCR_NUM" ] && [ -z "$PCR_VALUE" ]; then
    echo "ERROR: --pcr-value is required when using --pcr"
    exit 1
fi

if [ -z "$PCR_NUM" ] && [ -n "$PCR_VALUE" ]; then
    echo "ERROR: --pcr is required when using --pcr-value"
    exit 1
fi

# =============================================================================
# Main
# =============================================================================

print_banner() {
    echo "════════════════════════════════════════════════════════════════════"
    echo "  TPM2 Key Provisioning"
    echo "════════════════════════════════════════════════════════════════════"
    echo ""
}

check_existing_key() {
    if tpm2_readpublic -c "$TPM_HANDLE" &> /dev/null; then
        if is_keyvault_key "$TPM_HANDLE"; then
            return 0  # Our key exists
        else
            return 2  # Handle occupied by unknown key
        fi
    else
        return 1  # Handle is free
    fi
}

print_banner

# Check only mode
if [ "$CHECK_ONLY" = true ]; then
    echo "Checking for existing key at $TPM_HANDLE..."
    check_existing_key && result=0 || result=$?
    if [ $result -eq 0 ]; then
        echo ""
        echo "KeyVault key exists at $TPM_HANDLE"
        echo "Public key: $PUBLIC_KEY_PEM"
        if [ -f "$PCR_POLICY_FILE" ]; then
            echo "PCR policy: $(cat $PCR_POLICY_FILE)"
        fi
        exit 0
    elif [ $result -eq 2 ]; then
        echo "Handle occupied by unknown key"
        exit 2
    else
        echo "No key at $TPM_HANDLE"
        exit 1
    fi
fi

# Step counting (varies based on PCR policy)
if [ -n "$PCR_NUM" ]; then
    TOTAL_STEPS=8
else
    TOTAL_STEPS=7
fi
STEP=1

# Prerequisites
echo "[$STEP/$TOTAL_STEPS] Checking prerequisites..."
if ! check_tpm_prerequisites; then
    exit 1
fi
echo "       OK"
((STEP++))

# Show current state
echo ""
echo "[$STEP/$TOTAL_STEPS] Scanning TPM persistent storage..."
echo ""
list_persistent_handles
((STEP++))

# Check for existing key
echo "[$STEP/$TOTAL_STEPS] Checking for existing key at $TPM_HANDLE..."
check_existing_key && key_status=0 || key_status=$?

if [ $key_status -eq 0 ]; then
    # Our key exists
    if [ "$FORCE" = true ]; then
        echo "       --force specified, removing existing KeyVault key"
        remove_key "$TPM_HANDLE"
    else
        echo ""
        echo "KeyVault key already provisioned!"
        echo "Use --force to remove and recreate"
        exit 0
    fi
elif [ $key_status -eq 2 ]; then
    # Handle occupied by unknown key
    if [ "$FORCE" = true ]; then
        echo "       WARNING: --force specified, OVERWRITING unknown key!"
        remove_key "$TPM_HANDLE"
    else
        echo ""
        echo "  ┌─────────────────────────────────────────────────────────────┐"
        echo "  │  WARNING: Handle $TPM_HANDLE is OCCUPIED by unknown key!    │"
        echo "  │                                                             │"
        echo "  │  This may belong to another application.                    │"
        echo "  │  Use --force to overwrite, or --handle to use different one │"
        echo "  └─────────────────────────────────────────────────────────────┘"
        exit 1
    fi
else
    echo "       Handle $TPM_HANDLE is available"
fi
((STEP++))

# PCR Policy setup (if requested)
if [ -n "$PCR_NUM" ]; then
    echo ""
    echo "[$STEP/$TOTAL_STEPS] Setting up PCR policy..."
    setup_pcr_policy "$PCR_NUM" "$PCR_VALUE" "$FORCE"
    ((STEP++))
fi

# Create EK
echo ""
echo "[$STEP/$TOTAL_STEPS] Creating Endorsement Key (EK) context..."
create_ek
((STEP++))

# Create primary key
echo ""
echo "[$STEP/$TOTAL_STEPS] Creating primary storage key..."
create_primary_key
((STEP++))

# Create RSA key (with or without policy)
echo ""
echo "[$STEP/$TOTAL_STEPS] Creating RSA-2048 key..."
if [ -n "$PCR_NUM" ]; then
    create_rsa_key true  # With PCR policy
else
    create_rsa_key false # Without policy
fi
((STEP++))

# Load and persist
echo ""
echo "[$STEP/$TOTAL_STEPS] Loading and persisting key..."
load_and_persist_key "$TPM_HANDLE"
export_public_key "$TPM_HANDLE"

# Verification
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  Verification"
echo "════════════════════════════════════════════════════════════════════"
verify_key_operations "$TPM_HANDLE"

# Summary
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  Summary"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "TPM Key Handle:  $TPM_HANDLE"
echo "Public Key:      $PUBLIC_KEY_PEM"
echo "EK Context:      $EK_CTX (for encrypted sessions)"

if [ -n "$PCR_NUM" ]; then
    echo ""
    echo "PCR Policy:"
    echo "  PCR Number:    $PCR_NUM"
    echo "  Identity:      $PCR_VALUE"
    echo "  Config:        $PCR_POLICY_FILE"
    echo ""
    echo "IMPORTANT: Before using KeyVault, PCR $PCR_NUM must be extended with"
    echo "           the same value. Use: ./pcr.sh boot"
fi

echo ""
echo "Key Attributes:"
echo "  - fixedtpm: Key bound to THIS TPM only"
echo "  - sensitivedataorigin: Private key generated inside TPM"
echo "  - decrypt: Can decrypt data (for passphrase unwrapping)"
echo "  - sign: Can sign data (for authentication)"
if [ -n "$PCR_NUM" ]; then
    echo "  - PCR policy: Requires PCR $PCR_NUM to match provisioned value"
fi

echo ""
echo "Next Steps:"
if [ -n "$PCR_NUM" ]; then
    echo "  1. On each boot, run: ./pcr.sh boot"
    echo "  2. Then run KeyVault: ./source/build/key_vault_example"
else
    echo "  1. Build: mkdir -p source/build && cd source/build && cmake .. && make"
    echo "  2. Run: ./source/build/key_vault_example"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  Provisioning complete!"
echo "════════════════════════════════════════════════════════════════════"
