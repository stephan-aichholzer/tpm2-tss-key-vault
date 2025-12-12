#!/bin/bash
#
# init.sh - TPM2 Key Provisioning Script
#
# This script initializes the TPM2 for use with the KeyVault system.
# Run this ONCE during factory provisioning or initial device setup.
#
# What this script does:
#   1. Creates a primary storage key in the TPM
#   2. Creates an RSA-2048 key for encrypt/decrypt/sign operations
#   3. Persists the key at handle 0x81010002
#   4. Exports the public key as PEM for use by applications
#
# Prerequisites:
#   - TPM2 device accessible (/dev/tpm0 or /dev/tpmrm0)
#   - User in 'tss' group (or root)
#   - tpm2-tools package installed
#
# Usage:
#   ./init.sh                      # Normal initialization
#   ./init.sh --force              # Remove existing key and recreate
#   ./init.sh --check              # Check if key already exists
#   ./init.sh --list               # List all persistent handles in use
#   ./init.sh --handle 0x81010003  # Use a specific handle
#   ./init.sh --clear              # Remove KeyVault key from TPM
#
# Security Note:
#   The private key is generated INSIDE the TPM and NEVER leaves the chip.
#   Only the public key is exported to the filesystem.
#
# See Also:
#   - README.md for detailed explanation of each step
#   - CONCEPT_DOCUMENTATION.md for security architecture
#

set -e  # Exit on error

# =============================================================================
# Configuration
# =============================================================================

# Default TPM handle for the root RSA key (can be overridden with --handle)
DEFAULT_HANDLE="0x81010002"
TPM_HANDLE="$DEFAULT_HANDLE"

# KeyVault signature - used to identify keys we created
KEYVAULT_MARKER="KeyVault"

# Output directory for key files
KEY_DIR="keys"

# Temporary files (cleaned up on exit)
PRIMARY_CTX="/tmp/tpm_primary_$$.ctx"
KEY_PUB="/tmp/tpm_key_$$.pub"
KEY_PRIV="/tmp/tpm_key_$$.priv"
KEY_CTX="/tmp/tpm_key_$$.ctx"

# Output files
PUBLIC_KEY_PEM="${KEY_DIR}/tpm_rsa_pub.pem"
EK_CTX="${KEY_DIR}/ek.ctx"
EK_PUB="${KEY_DIR}/ek.pub"

# =============================================================================
# Functions
# =============================================================================

cleanup() {
    # Remove temporary files
    rm -f "$PRIMARY_CTX" "$KEY_PUB" "$KEY_PRIV" "$KEY_CTX" 2>/dev/null || true
}

trap cleanup EXIT

print_banner() {
    echo "========================================"
    echo "  TPM2 Key Provisioning"
    echo "========================================"
    echo ""
}

check_prerequisites() {
    echo "[1/7] Checking prerequisites..."

    # Check for tpm2-tools
    if ! command -v tpm2_createprimary &> /dev/null; then
        echo "ERROR: tpm2-tools not installed"
        echo "Install with: sudo apt install tpm2-tools"
        exit 1
    fi

    # Check TPM access
    if ! tpm2_getrandom 4 --hex &> /dev/null; then
        echo "ERROR: Cannot access TPM"
        echo "Ensure you are in the 'tss' group: sudo usermod -aG tss \$USER"
        echo "Then log out and log back in"
        exit 1
    fi

    echo "       Prerequisites OK"
}

list_persistent_handles() {
    echo ""
    echo "Persistent handles currently in use:"
    echo "─────────────────────────────────────────────────────────────────"

    local handles=$(tpm2_getcap handles-persistent 2>/dev/null | grep "0x" | tr -d ' -')

    if [ -z "$handles" ]; then
        echo "  (none)"
    else
        printf "  %-14s  %-8s  %-6s  %s\n" "Handle" "Type" "Bits" "Attributes"
        echo "  ─────────────────────────────────────────────────────────────"

        for handle in $handles; do
            local info=$(tpm2_readpublic -c "$handle" 2>/dev/null)
            local type=$(echo "$info" | grep -A1 "^type:" | tail -1 | sed 's/.*value: //')
            local bits=$(echo "$info" | grep "^bits:" | awk '{print $2}')
            local attrs=$(echo "$info" | grep -A1 "^attributes:" | tail -1 | sed 's/.*value: //' | cut -c1-30)

            # Check if this is our target handle
            if [ "$handle" = "$TPM_HANDLE" ]; then
                printf "  %-14s  %-8s  %-6s  %s  ← target\n" "$handle" "$type" "$bits" "$attrs"
            else
                printf "  %-14s  %-8s  %-6s  %s\n" "$handle" "$type" "$bits" "$attrs"
            fi
        done
    fi
    echo ""
}

is_keyvault_key() {
    # Check if the key at the given handle looks like a KeyVault key
    # We identify by: RSA-2048, has decrypt+sign attributes
    local handle="$1"
    local info=$(tpm2_readpublic -c "$handle" 2>/dev/null)

    if [ -z "$info" ]; then
        return 1  # No key at handle
    fi

    local type=$(echo "$info" | grep -A1 "^type:" | tail -1 | sed 's/.*value: //')
    local bits=$(echo "$info" | grep "^bits:" | awk '{print $2}')
    local attrs=$(echo "$info" | grep -A1 "^attributes:" | tail -1 | sed 's/.*value: //')

    # Check if it matches our KeyVault key profile
    if [[ "$type" == "rsa" && "$bits" == "2048" && "$attrs" == *"decrypt"* && "$attrs" == *"sign"* ]]; then
        return 0  # Looks like ours
    fi

    return 1  # Doesn't match our profile
}

check_existing_key() {
    echo "[3/8] Checking for existing key at $TPM_HANDLE..."

    if tpm2_readpublic -c "$TPM_HANDLE" &> /dev/null; then
        if is_keyvault_key "$TPM_HANDLE"; then
            echo "       KeyVault key exists at $TPM_HANDLE"
            return 0  # Our key exists
        else
            echo ""
            echo "  ┌─────────────────────────────────────────────────────────────┐"
            echo "  │  WARNING: Handle $TPM_HANDLE is OCCUPIED by unknown key!    │"
            echo "  │                                                             │"
            echo "  │  This may belong to another application. Overwriting it     │"
            echo "  │  could break other software on this system.                 │"
            echo "  │                                                             │"
            echo "  │  Options:                                                   │"
            echo "  │    1. Use --handle 0x810100XX to pick a different handle    │"
            echo "  │    2. Use --list to see all handles in use                  │"
            echo "  │    3. Use --force if you're SURE you want to overwrite      │"
            echo "  └─────────────────────────────────────────────────────────────┘"
            echo ""
            return 2  # Occupied by unknown key
        fi
    else
        echo "       Handle $TPM_HANDLE is available"
        return 1  # Handle is free
    fi
}

remove_existing_key() {
    echo "       Removing existing key..."
    tpm2_evictcontrol -C o -c "$TPM_HANDLE" 2>/dev/null || true
    echo "       Key removed"
}

clear_keyvault_key() {
    echo ""
    echo "Clearing KeyVault key at $TPM_HANDLE..."
    echo ""

    # Check if key exists
    if ! tpm2_readpublic -c "$TPM_HANDLE" &> /dev/null; then
        echo "No key found at $TPM_HANDLE - nothing to clear"
        return 1
    fi

    # Check if it's our key (unless --force)
    if [ "$FORCE" != true ]; then
        if ! is_keyvault_key "$TPM_HANDLE"; then
            echo "  ┌─────────────────────────────────────────────────────────────┐"
            echo "  │  WARNING: Key at $TPM_HANDLE doesn't look like KeyVault!    │"
            echo "  │                                                             │"
            echo "  │  This may belong to another application.                    │"
            echo "  │  Use --force --clear if you're SURE you want to remove it.  │"
            echo "  └─────────────────────────────────────────────────────────────┘"
            return 2
        fi
    fi

    # Remove the key
    if tpm2_evictcontrol -C o -c "$TPM_HANDLE" 2>/dev/null; then
        echo "Key removed from TPM at $TPM_HANDLE"

        # Also clean up local files if they exist
        if [ -f "$PUBLIC_KEY_PEM" ]; then
            rm -f "$PUBLIC_KEY_PEM"
            echo "Removed: $PUBLIC_KEY_PEM"
        fi
        if [ -f "$EK_CTX" ]; then
            rm -f "$EK_CTX"
            echo "Removed: $EK_CTX"
        fi
        if [ -f "$EK_PUB" ]; then
            rm -f "$EK_PUB"
            echo "Removed: $EK_PUB"
        fi

        echo ""
        echo "KeyVault cleared. Run ./init.sh to re-provision."
        return 0
    else
        echo "ERROR: Failed to remove key"
        return 1
    fi
}

create_ek() {
    echo "[4/8] Creating Endorsement Key (EK) context..."

    # Create/load EK - used for encrypted session key agreement
    # The EK is derived from TPM's burned-in seed (same every time)
    # This doesn't "create" a new key, it loads the existing factory EK
    tpm2_createek \
        -c "$EK_CTX" \
        -G rsa \
        -u "$EK_PUB" \
        > /dev/null

    echo "       EK context created (for encrypted sessions)"
}

create_primary_key() {
    echo "[5/8] Creating primary storage key..."

    # Create primary key under owner hierarchy
    # This key is derived from TPM's internal seed (deterministic)
    tpm2_createprimary \
        -C o \
        -g sha256 \
        -G rsa \
        -c "$PRIMARY_CTX" \
        > /dev/null

    echo "       Primary key created"
}

create_rsa_key() {
    echo "[6/8] Creating RSA-2048 key with sign+decrypt attributes..."

    # Create RSA key with the following attributes:
    #   fixedtpm           - Key can only be used on this TPM
    #   fixedparent        - Key cannot be moved to different parent
    #   sensitivedataorigin - Private key generated inside TPM
    #   userwithauth       - Can use with authorization
    #   decrypt            - Key can decrypt data
    #   sign               - Key can sign data
    tpm2_create \
        -C "$PRIMARY_CTX" \
        -G rsa2048 \
        -u "$KEY_PUB" \
        -r "$KEY_PRIV" \
        -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign" \
        > /dev/null

    echo "       RSA key created (private key is inside TPM)"
}

load_and_persist_key() {
    echo "[7/8] Loading and persisting key at $TPM_HANDLE..."

    # Load key into TPM
    tpm2_load \
        -C "$PRIMARY_CTX" \
        -u "$KEY_PUB" \
        -r "$KEY_PRIV" \
        -c "$KEY_CTX" \
        > /dev/null

    # Persist at specified handle (survives reboot)
    tpm2_evictcontrol \
        -C o \
        -c "$KEY_CTX" \
        "$TPM_HANDLE" \
        > /dev/null

    echo "       Key persisted at $TPM_HANDLE"
}

export_public_key() {
    echo "[8/8] Exporting public key to $PUBLIC_KEY_PEM..."

    # Create output directory if needed
    mkdir -p "$KEY_DIR"

    # Export public key as PEM
    tpm2_readpublic \
        -c "$TPM_HANDLE" \
        -f pem \
        -o "$PUBLIC_KEY_PEM" \
        > /dev/null

    echo "       Public key exported"
}

verify_key() {
    echo ""
    echo "========================================"
    echo "  Verification"
    echo "========================================"
    echo ""

    echo "Testing TPM key operations..."
    echo ""

    # Test sign operation
    echo "Sign test:"
    echo "Hello TPM" | tpm2_sign \
        -c "$TPM_HANDLE" \
        -g sha256 \
        -o /tmp/test_sig_$$.bin \
        - 2>/dev/null && echo "  Sign: OK" || echo "  Sign: FAILED"
    rm -f /tmp/test_sig_$$.bin

    # Test encrypt/decrypt
    echo ""
    echo "Encrypt/Decrypt test:"
    echo -n "TestSecret" > /tmp/test_plain_$$.txt

    openssl pkeyutl -encrypt \
        -pubin -inkey "$PUBLIC_KEY_PEM" \
        -in /tmp/test_plain_$$.txt \
        -out /tmp/test_enc_$$.bin 2>/dev/null

    openssl pkeyutl -provider tpm2 -provider default \
        -decrypt \
        -inkey "handle:$TPM_HANDLE" \
        -in /tmp/test_enc_$$.bin \
        -out /tmp/test_dec_$$.txt 2>/dev/null

    if diff -q /tmp/test_plain_$$.txt /tmp/test_dec_$$.txt > /dev/null 2>&1; then
        echo "  Encrypt/Decrypt: OK"
    else
        echo "  Encrypt/Decrypt: FAILED"
    fi

    rm -f /tmp/test_plain_$$.txt /tmp/test_enc_$$.bin /tmp/test_dec_$$.txt
}

print_summary() {
    echo ""
    echo "========================================"
    echo "  Summary"
    echo "========================================"
    echo ""
    echo "TPM Key Handle:  $TPM_HANDLE"
    echo "Public Key:      $PUBLIC_KEY_PEM"
    echo "EK Context:      $EK_CTX (for encrypted sessions)"
    echo ""
    echo "Key Attributes:"
    echo "  - fixedtpm: Key bound to THIS TPM only"
    echo "  - sensitivedataorigin: Private key generated inside TPM"
    echo "  - decrypt: Can decrypt data (for passphrase unwrapping)"
    echo "  - sign: Can sign data (for authentication)"
    echo ""
    echo "Endorsement Key (EK):"
    echo "  - Factory-burned key for TPM identity"
    echo "  - Used for encrypted session key agreement"
    echo "  - Protects bus communication against sniffing"
    echo ""
    echo "Next Steps:"
    echo "  1. Build: mkdir -p source/build && cd source/build && cmake .. && make"
    echo "  2. From project root, run: ./source/build/tpm_example"
    echo "  3. Full demo: ./source/build/key_vault_example"
    echo ""
    echo "Security Note:"
    echo "  The private key exists ONLY inside the TPM chip."
    echo "  It cannot be extracted or cloned to another device."
    echo "  Bus traffic is encrypted using EK-derived session keys."
    echo ""
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --check              Check if key exists (exit 0 if yes, 1 if no)"
    echo "  --clear              Remove KeyVault key from TPM and clean up files"
    echo "  --force              Force operation (overwrite/remove without safety checks)"
    echo "  --list               List all persistent handles currently in use"
    echo "  --handle 0x810100XX  Use a specific handle (default: $DEFAULT_HANDLE)"
    echo "  --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                   # Provision new key at default handle"
    echo "  $0 --list            # See what's in the TPM"
    echo "  $0 --clear           # Remove KeyVault key and files"
    echo "  $0 --handle 0x81010003 --clear  # Remove key at specific handle"
    echo ""
    echo "Handle ranges (by convention):"
    echo "  0x81000000-0x810000FF  Owner hierarchy (SRK, system keys)"
    echo "  0x81010000-0x810100FF  Endorsement hierarchy (EK, app keys)"
    echo "  0x81800000-0x818000FF  Platform hierarchy (firmware)"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

print_banner

# Parse arguments
FORCE=false
CHECK_ONLY=false
LIST_ONLY=false
CLEAR_MODE=false

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
        --clear)
            CLEAR_MODE=true
            shift
            ;;
        --list)
            LIST_ONLY=true
            shift
            ;;
        --handle)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "ERROR: --handle requires a value (e.g., --handle 0x81010003)"
                exit 1
            fi
            # Validate handle format
            if [[ ! "$2" =~ ^0x81[0-9a-fA-F]{6}$ ]]; then
                echo "ERROR: Invalid handle format: $2"
                echo "       Expected format: 0x81XXXXXX (e.g., 0x81010002)"
                exit 1
            fi
            TPM_HANDLE="$2"
            shift 2
            ;;
        --help)
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

# List only mode
if [ "$LIST_ONLY" = true ]; then
    list_persistent_handles
    echo "Target handle: $TPM_HANDLE"
    echo ""
    exit 0
fi

# Clear mode
if [ "$CLEAR_MODE" = true ]; then
    clear_keyvault_key && exit 0 || exit $?
fi

# Check only mode
if [ "$CHECK_ONLY" = true ]; then
    check_existing_key && result=0 || result=$?
    if [ $result -eq 0 ]; then
        echo ""
        echo "KeyVault key exists at $TPM_HANDLE"
        echo "Public key: $PUBLIC_KEY_PEM"
        exit 0
    elif [ $result -eq 2 ]; then
        echo "Handle occupied by unknown key"
        exit 2
    else
        echo ""
        echo "No key at $TPM_HANDLE"
        exit 1
    fi
fi

# Normal provisioning
check_prerequisites

# Show what's currently in use
echo ""
echo "[2/8] Scanning TPM persistent storage..."
list_persistent_handles

check_existing_key && key_status=0 || key_status=$?

if [ $key_status -eq 0 ]; then
    # Our key exists
    if [ "$FORCE" = true ]; then
        echo "WARNING: --force specified, removing existing KeyVault key"
        remove_existing_key
    else
        echo ""
        echo "KeyVault key already provisioned!"
        echo "Use --force to remove and recreate, or --check to verify"
        print_summary
        exit 0
    fi
elif [ $key_status -eq 2 ]; then
    # Handle occupied by unknown key
    if [ "$FORCE" = true ]; then
        echo "WARNING: --force specified, OVERWRITING unknown key!"
        echo "         (Hope you know what you're doing...)"
        remove_existing_key
    else
        echo "Aborting to avoid overwriting unknown key."
        echo ""
        echo "Suggested free handles:"
        # Find a few free handles to suggest
        for try_handle in 0x81010002 0x81010003 0x81010004 0x81010005; do
            if ! tpm2_readpublic -c "$try_handle" &> /dev/null; then
                echo "  $try_handle  (available)"
            fi
        done
        echo ""
        echo "Use: $0 --handle 0x810100XX"
        exit 1
    fi
fi
# else: key_status -eq 1 means handle is free, proceed

echo ""
create_ek
create_primary_key
create_rsa_key
load_and_persist_key
export_public_key

verify_key
print_summary

echo "Provisioning complete!"
