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
#   ./init.sh              # Normal initialization
#   ./init.sh --force      # Remove existing key and recreate
#   ./init.sh --check      # Check if key already exists
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

# TPM handle for the root RSA key
TPM_HANDLE="0x81010002"

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

check_existing_key() {
    echo "[2/7] Checking for existing key at $TPM_HANDLE..."

    if tpm2_readpublic -c "$TPM_HANDLE" &> /dev/null; then
        echo "       Key already exists at $TPM_HANDLE"
        return 0
    else
        echo "       No existing key found"
        return 1
    fi
}

remove_existing_key() {
    echo "       Removing existing key..."
    tpm2_evictcontrol -C o -c "$TPM_HANDLE" 2>/dev/null || true
    echo "       Key removed"
}

create_ek() {
    echo "[3/7] Creating Endorsement Key (EK) context..."

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
    echo "[4/7] Creating primary storage key..."

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
    echo "[5/7] Creating RSA-2048 key with sign+decrypt attributes..."

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
    echo "[6/7] Loading and persisting key at $TPM_HANDLE..."

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
    echo "[7/7] Exporting public key to $PUBLIC_KEY_PEM..."

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
    echo "  1. Build the C++ examples: cd build && cmake .. && make"
    echo "  2. Run basic test: ./tpm_example"
    echo "  3. Run full demo: ./key_vault_example"
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
    echo "  --check    Check if key exists (exit 0 if yes, 1 if no)"
    echo "  --force    Remove existing key and create new one"
    echo "  --help     Show this help message"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

print_banner

# Parse arguments
FORCE=false
CHECK_ONLY=false

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

# Check only mode
if [ "$CHECK_ONLY" = true ]; then
    if check_existing_key; then
        echo ""
        echo "Key exists at $TPM_HANDLE"
        echo "Public key: $PUBLIC_KEY_PEM"
        exit 0
    else
        echo ""
        echo "No key at $TPM_HANDLE"
        exit 1
    fi
fi

# Normal provisioning
check_prerequisites

if check_existing_key; then
    if [ "$FORCE" = true ]; then
        echo ""
        echo "WARNING: --force specified, removing existing key"
        remove_existing_key
    else
        echo ""
        echo "Key already provisioned!"
        echo "Use --force to remove and recreate, or --check to verify"
        print_summary
        exit 0
    fi
fi

echo ""
create_ek
create_primary_key
create_rsa_key
load_and_persist_key
export_public_key

verify_key
print_summary

echo "Provisioning complete!"
