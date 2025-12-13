#!/bin/bash
#
# tpm_lib.sh - Shared TPM2 Functions Library
#
# This file contains common functions used by TPM2 provisioning scripts.
# Source this file from other scripts: source ./tpm_lib.sh
#
# Functions:
#   - Configuration and cleanup
#   - Key identification and listing
#   - PCR operations
#   - Key creation and management
#

# =============================================================================
# Configuration (can be overridden before sourcing)
# =============================================================================

# Default TPM handle for KeyVault key
: "${TPM_HANDLE:=0x81010002}"
: "${DEFAULT_HANDLE:=0x81010002}"

# Output directory for key files
: "${KEY_DIR:=keys}"

# Output files
: "${PUBLIC_KEY_PEM:=${KEY_DIR}/tpm_rsa_pub.pem}"
: "${EK_CTX:=${KEY_DIR}/ek.ctx}"
: "${EK_PUB:=${KEY_DIR}/ek.pub}"
: "${PCR_POLICY_FILE:=${KEY_DIR}/pcr_policy}"
: "${PCR_VALUE_FILE:=${KEY_DIR}/pcr_value}"

# Temporary files (use $$ for unique names per process)
: "${PRIMARY_CTX:=/tmp/tpm_primary_$$.ctx}"
: "${KEY_PUB:=/tmp/tpm_key_$$.pub}"
: "${KEY_PRIV:=/tmp/tpm_key_$$.priv}"
: "${KEY_CTX:=/tmp/tpm_key_$$.ctx}"
: "${POLICY_SESSION:=/tmp/tpm_policy_session_$$.ctx}"
: "${POLICY_DIGEST:=/tmp/tpm_policy_digest_$$.bin}"

# =============================================================================
# Cleanup
# =============================================================================

tpm_cleanup() {
    rm -f "$PRIMARY_CTX" "$KEY_PUB" "$KEY_PRIV" "$KEY_CTX" 2>/dev/null || true
    rm -f "$POLICY_SESSION" "$POLICY_DIGEST" 2>/dev/null || true
    tpm2_flushcontext -s 2>/dev/null || true
}

# =============================================================================
# Prerequisites
# =============================================================================

check_tpm_prerequisites() {
    # Check for tpm2-tools
    if ! command -v tpm2_createprimary &> /dev/null; then
        echo "ERROR: tpm2-tools not installed"
        echo "Install with: sudo apt install tpm2-tools"
        return 1
    fi

    # Check TPM access
    if ! tpm2_getrandom 4 --hex &> /dev/null; then
        echo "ERROR: Cannot access TPM"
        echo "Ensure you are in the 'tss' group: sudo usermod -aG tss \$USER"
        echo "Then log out and log back in"
        return 1
    fi

    return 0
}

# =============================================================================
# Key Identification
# =============================================================================

identify_key_purpose() {
    # Identify key purpose based on handle and attributes
    local handle="$1"
    local attrs="$2"

    # Check by well-known handles first
    case "$handle" in
        0x81000001)
            echo "SRK"      # Storage Root Key
            return
            ;;
        0x81000002)
            if [[ "$attrs" == *"restricted"* && "$attrs" == *"sign"* ]]; then
                echo "AK"   # Attestation Key
            else
                echo "sys"
            fi
            return
            ;;
        0x81010001)
            if [[ "$attrs" == *"restricted"* && "$attrs" == *"decrypt"* ]]; then
                echo "EK"   # Endorsement Key (persisted)
            else
                echo "?"
            fi
            return
            ;;
    esac

    # Check if it's our KeyVault key
    if [ "$handle" = "$TPM_HANDLE" ]; then
        if is_keyvault_key "$handle"; then
            echo "KV"       # KeyVault
            return
        fi
    fi

    # Check by attributes for unknown handles
    if [[ "$attrs" == *"restricted"* && "$attrs" == *"decrypt"* && "$attrs" != *"sign"* ]]; then
        echo "EK?"          # Looks like EK
    elif [[ "$attrs" == *"restricted"* && "$attrs" == *"sign"* && "$attrs" != *"decrypt"* ]]; then
        echo "AK?"          # Looks like AK
    elif [[ "$attrs" == *"restricted"* && "$attrs" == *"decrypt"* ]]; then
        echo "SRK?"         # Looks like storage key
    elif [[ "$attrs" == *"decrypt"* && "$attrs" == *"sign"* ]]; then
        echo "app"          # Application key
    else
        echo "?"
    fi
}

is_keyvault_key() {
    # Check if the key at the given handle looks like a KeyVault key
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

# =============================================================================
# Handle Listing
# =============================================================================

list_persistent_handles() {
    local show_target="${1:-true}"

    echo "Persistent handles currently in use:"
    echo "───────────────────────────────────────────────────────────────────────"

    local handles=$(tpm2_getcap handles-persistent 2>/dev/null | grep "0x" | tr -d ' -')

    if [ -z "$handles" ]; then
        echo "  (none)"
    else
        printf "  %-14s  %-6s  %-8s  %-6s  %s\n" "Handle" "Key" "Type" "Bits" "Attributes"
        echo "  ───────────────────────────────────────────────────────────────────"

        for handle in $handles; do
            local info=$(tpm2_readpublic -c "$handle" 2>/dev/null)
            local type=$(echo "$info" | grep -A1 "^type:" | tail -1 | sed 's/.*value: //')
            local bits=$(echo "$info" | grep "^bits:" | awk '{print $2}')
            local attrs=$(echo "$info" | grep -A1 "^attributes:" | tail -1 | sed 's/.*value: //')
            local attrs_short=$(echo "$attrs" | cut -c1-26)
            local purpose=$(identify_key_purpose "$handle" "$attrs")

            if [ "$show_target" = "true" ] && [ "$handle" = "$TPM_HANDLE" ]; then
                printf "  %-14s  %-6s  %-8s  %-6s  %s  <- target\n" "$handle" "$purpose" "$type" "$bits" "$attrs_short"
            else
                printf "  %-14s  %-6s  %-8s  %-6s  %s\n" "$handle" "$purpose" "$type" "$bits" "$attrs_short"
            fi
        done
    fi
    echo ""
    echo "Key types: SRK=Storage Root, EK=Endorsement, AK=Attestation, KV=KeyVault, app=application"
}

# =============================================================================
# PCR Operations
# =============================================================================

pcr_read() {
    # Read and display PCR value
    local pcr_num="$1"

    if ! [[ "$pcr_num" =~ ^[0-9]+$ ]] || [ "$pcr_num" -gt 23 ]; then
        echo "ERROR: Invalid PCR number: $pcr_num (must be 0-23)"
        return 1
    fi

    tpm2_pcrread sha256:$pcr_num
}

pcr_reset() {
    # Reset PCR (only works for PCR 16)
    local pcr_num="$1"

    if [ "$pcr_num" != "16" ]; then
        echo "ERROR: Only PCR 16 (debug PCR) can be reset by software"
        echo "       PCRs 0-15 require hardware reboot to reset"
        return 1
    fi

    tpm2_pcrreset 16 > /dev/null 2>&1
    echo "PCR 16 reset to zero"
}

pcr_extend() {
    # Extend PCR with a value
    local pcr_num="$1"
    local value="$2"

    if ! [[ "$pcr_num" =~ ^[0-9]+$ ]] || [ "$pcr_num" -gt 23 ]; then
        echo "ERROR: Invalid PCR number: $pcr_num (must be 0-23)"
        return 1
    fi

    if [ -z "$value" ]; then
        echo "ERROR: Value required"
        return 1
    fi

    local value_hash=$(echo -n "$value" | sha256sum | cut -d' ' -f1)
    tpm2_pcrextend ${pcr_num}:sha256=$value_hash > /dev/null

    echo "PCR $pcr_num extended with hash of: $value"
    echo "Hash: $value_hash"
}

pcr_is_zero() {
    # Check if PCR is all zeros (fresh boot state)
    local pcr_num="$1"

    local current_pcr=$(tpm2_pcrread sha256:$pcr_num -o /dev/stdout 2>/dev/null | xxd -p | tr -d '\n')
    local zero_pcr=$(printf '0%.0s' {1..64})  # 32 bytes = 64 hex chars

    [ "$current_pcr" = "$zero_pcr" ]
}

# =============================================================================
# PCR Policy Creation
# =============================================================================

setup_pcr_policy() {
    # Set up PCR with value and create policy digest
    # Returns: sets POLICY_DIGEST file path
    local pcr_num="$1"
    local pcr_value="$2"
    local force="${3:-false}"

    # Validate PCR number
    if ! [[ "$pcr_num" =~ ^(14|15|16)$ ]]; then
        echo "ERROR: PCR must be 14, 15, or 16"
        return 1
    fi

    # For PCR 16, reset it first (demo mode)
    if [ "$pcr_num" = "16" ]; then
        echo "Resetting PCR 16 (debug PCR)..."
        tpm2_pcrreset 16 > /dev/null 2>&1 || {
            echo "ERROR: Failed to reset PCR 16"
            return 1
        }
    else
        # For PCR 14/15, check if fresh boot
        echo ""
        echo "  ┌─────────────────────────────────────────────────────────────┐"
        echo "  │  NOTE: PCR $pcr_num can only be reset by hardware reboot     │"
        echo "  │  Ensure this device was freshly booted before provisioning! │"
        echo "  └─────────────────────────────────────────────────────────────┘"
        echo ""

        if ! pcr_is_zero "$pcr_num"; then
            echo "  WARNING: PCR $pcr_num is not zero - system may not be freshly booted"
            if [ "$force" != "true" ]; then
                echo "  Use --force to proceed anyway"
                return 1
            fi
            echo "  --force specified, proceeding..."
        fi
    fi

    # Extend PCR with the identity value
    echo "Extending PCR $pcr_num with identity value..."
    local value_hash=$(echo -n "$pcr_value" | sha256sum | cut -d' ' -f1)
    tpm2_pcrextend ${pcr_num}:sha256=$value_hash > /dev/null

    # Create policy digest
    echo "Creating PCR policy digest..."

    # Start a trial policy session
    tpm2_startauthsession -S "$POLICY_SESSION" --policy-session > /dev/null

    # Add PCR policy - captures current PCR value into policy
    tpm2_policypcr -S "$POLICY_SESSION" -l sha256:$pcr_num -L "$POLICY_DIGEST" > /dev/null

    # Flush the session
    tpm2_flushcontext "$POLICY_SESSION" > /dev/null 2>&1 || true

    # Save PCR config
    mkdir -p "$KEY_DIR"
    echo "$pcr_num" > "$PCR_POLICY_FILE"
    echo "$pcr_value" > "$PCR_VALUE_FILE"

    echo "PCR policy created and saved"
    echo "  PCR:   $pcr_num"
    echo "  Value: $pcr_value"
    echo "  Hash:  $value_hash"
}

# =============================================================================
# Key Creation
# =============================================================================

create_ek() {
    # Create Endorsement Key context (for encrypted sessions)
    mkdir -p "$KEY_DIR"

    tpm2_createek \
        -c "$EK_CTX" \
        -G rsa \
        -u "$EK_PUB" \
        > /dev/null

    echo "EK context created: $EK_CTX"
}

create_primary_key() {
    # Create primary storage key under owner hierarchy
    tpm2_createprimary \
        -C o \
        -g sha256 \
        -G rsa \
        -c "$PRIMARY_CTX" \
        > /dev/null

    echo "Primary key created"
}

create_rsa_key() {
    # Create RSA-2048 key with optional PCR policy
    local with_policy="${1:-false}"

    local attrs="fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign"

    if [ "$with_policy" = "true" ] && [ -f "$POLICY_DIGEST" ]; then
        # Create key with PCR policy
        # Note: remove userwithauth when using policy
        attrs="fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"

        tpm2_create \
            -C "$PRIMARY_CTX" \
            -G rsa2048 \
            -u "$KEY_PUB" \
            -r "$KEY_PRIV" \
            -L "$POLICY_DIGEST" \
            -a "$attrs" \
            > /dev/null

        echo "RSA key created with PCR policy"
    else
        # Create key without policy
        tpm2_create \
            -C "$PRIMARY_CTX" \
            -G rsa2048 \
            -u "$KEY_PUB" \
            -r "$KEY_PRIV" \
            -a "$attrs" \
            > /dev/null

        echo "RSA key created (no PCR policy)"
    fi
}

load_and_persist_key() {
    # Load key and persist at handle
    local handle="${1:-$TPM_HANDLE}"

    # Load key into TPM
    tpm2_load \
        -C "$PRIMARY_CTX" \
        -u "$KEY_PUB" \
        -r "$KEY_PRIV" \
        -c "$KEY_CTX" \
        > /dev/null

    # Persist at handle
    tpm2_evictcontrol \
        -C o \
        -c "$KEY_CTX" \
        "$handle" \
        > /dev/null

    echo "Key persisted at $handle"
}

export_public_key() {
    # Export public key as PEM
    local handle="${1:-$TPM_HANDLE}"

    mkdir -p "$KEY_DIR"

    tpm2_readpublic \
        -c "$handle" \
        -f pem \
        -o "$PUBLIC_KEY_PEM" \
        > /dev/null

    echo "Public key exported: $PUBLIC_KEY_PEM"
}

remove_key() {
    # Remove key from TPM
    local handle="${1:-$TPM_HANDLE}"

    tpm2_evictcontrol -C o -c "$handle" 2>/dev/null
}

# =============================================================================
# Verification
# =============================================================================

verify_key_operations() {
    # Test sign and encrypt/decrypt operations
    local handle="${1:-$TPM_HANDLE}"
    local pcr_num=""

    # Check if PCR policy is in use
    if [ -f "$PCR_POLICY_FILE" ]; then
        pcr_num=$(cat "$PCR_POLICY_FILE")
        echo "Note: Key has PCR $pcr_num policy"
    fi

    echo ""
    echo "Testing TPM key operations..."
    echo ""

    # Test sign operation
    echo "Sign test:"
    echo "Hello TPM" > /tmp/test_msg_$$.txt
    if tpm2_sign -c "$handle" -g sha256 -o /tmp/test_sig_$$.bin /tmp/test_msg_$$.txt 2>/dev/null; then
        echo "  Sign: OK"
    else
        echo "  Sign: FAILED (may require PCR policy session)"
    fi
    rm -f /tmp/test_sig_$$.bin /tmp/test_msg_$$.txt

    # Test encrypt/decrypt
    echo ""
    echo "Encrypt/Decrypt test:"
    echo -n "TestSecret" > /tmp/test_plain_$$.txt

    openssl pkeyutl -encrypt \
        -pubin -inkey "$PUBLIC_KEY_PEM" \
        -in /tmp/test_plain_$$.txt \
        -out /tmp/test_enc_$$.bin 2>/dev/null

    if openssl pkeyutl -provider tpm2 -provider default \
        -decrypt \
        -inkey "handle:$handle" \
        -in /tmp/test_enc_$$.bin \
        -out /tmp/test_dec_$$.txt 2>/dev/null; then

        if diff -q /tmp/test_plain_$$.txt /tmp/test_dec_$$.txt > /dev/null 2>&1; then
            echo "  Encrypt/Decrypt: OK"
        else
            echo "  Encrypt/Decrypt: FAILED (content mismatch)"
        fi
    else
        echo "  Encrypt/Decrypt: FAILED (may require PCR policy session)"
    fi

    rm -f /tmp/test_plain_$$.txt /tmp/test_enc_$$.bin /tmp/test_dec_$$.txt
}
