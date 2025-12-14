#!/bin/bash
#
# tpm2_status.sh - Return TPM2 chip status as JSON
#
# Usage:
#   ./tpm2_status.sh              # Output JSON to stdout
#   ./tpm2_status.sh --pretty     # Pretty-printed JSON
#   ./tpm2_status.sh --check      # Exit 0 if TPM accessible, 1 otherwise
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
PRETTY=false
CHECK_ONLY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --pretty|-p)
            PRETTY=true
            shift
            ;;
        --check|-c)
            CHECK_ONLY=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --pretty, -p    Pretty-print JSON output"
            echo "  --check, -c     Exit 0 if TPM accessible, 1 otherwise"
            echo "  --help, -h      Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Quick check mode
if [ "$CHECK_ONLY" = true ]; then
    if tpm2_getrandom 1 &>/dev/null; then
        exit 0
    else
        exit 1
    fi
fi

# Helper: escape string for JSON
json_escape() {
    printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()), end="")' 2>/dev/null || \
    printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\n/\\n/g')"
}

# Helper: safe command execution, returns empty string on failure
safe_cmd() {
    "$@" 2>/dev/null || echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Collect Device Information
# ─────────────────────────────────────────────────────────────────────────────

DEVICE_TPM0="false"
DEVICE_TPMRM0="false"
[ -c /dev/tpm0 ] && DEVICE_TPM0="true"
[ -c /dev/tpmrm0 ] && DEVICE_TPMRM0="true"

# Manufacturer info from properties-fixed
PROPS_FIXED=$(tpm2_getcap properties-fixed 2>/dev/null || echo "")

get_prop() {
    echo "$PROPS_FIXED" | grep -A1 "$1" | tail -1 | awk '{print $2}'
}

get_prop_string() {
    local val=$(get_prop "$1")
    [ -n "$val" ] && echo "$val" | xxd -r -p 2>/dev/null || echo ""
}

MANUFACTURER=$(get_prop_string "TPM2_PT_MANUFACTURER")
VENDOR_STRING="${MANUFACTURER}$(get_prop_string TPM2_PT_VENDOR_STRING_1)$(get_prop_string TPM2_PT_VENDOR_STRING_2)$(get_prop_string TPM2_PT_VENDOR_STRING_3)$(get_prop_string TPM2_PT_VENDOR_STRING_4)"

# Firmware version
FW_V1=$(get_prop "TPM2_PT_FIRMWARE_VERSION_1")
FW_V2=$(get_prop "TPM2_PT_FIRMWARE_VERSION_2")
FW_VERSION=""
if [ -n "$FW_V1" ] && [ "$FW_V1" != "0" ]; then
    FW_V1_CLEAN=$(echo "$FW_V1" | sed 's/^0x//')
    FW_MAJOR=$(printf "%d" $((16#${FW_V1_CLEAN:0:4})) 2>/dev/null || echo "0")
    FW_MINOR=$(printf "%d" $((16#${FW_V1_CLEAN:4:4})) 2>/dev/null || echo "0")
    FW_VERSION="${FW_MAJOR}.${FW_MINOR}"
fi

# Spec version
SPEC_FAMILY=$(get_prop "TPM2_PT_FAMILY_INDICATOR")
SPEC_LEVEL=$(get_prop "TPM2_PT_LEVEL")
SPEC_REV=$(get_prop "TPM2_PT_REVISION")
SPEC_VERSION=""
if [ -n "$SPEC_REV" ]; then
    SPEC_REV_DEC=$((SPEC_REV))
    SPEC_VERSION="$((SPEC_REV_DEC / 100)).$((SPEC_REV_DEC % 100))"
fi

# Year/day of manufacture (convert hex to decimal)
YEAR_HEX=$(get_prop "TPM2_PT_YEAR")
DAY_HEX=$(get_prop "TPM2_PT_DAY_OF_YEAR")
YEAR=""
DAY=""
[ -n "$YEAR_HEX" ] && YEAR=$((YEAR_HEX))
[ -n "$DAY_HEX" ] && DAY=$((DAY_HEX))

# Bus type detection
BUS_TYPE="unknown"
if [ -d /sys/class/tpm/tpm0/device ]; then
    BUS_PATH=$(readlink -f /sys/class/tpm/tpm0/device 2>/dev/null || echo "")
    if echo "$BUS_PATH" | grep -qi "spi"; then
        BUS_TYPE="spi"
    elif echo "$BUS_PATH" | grep -qi "i2c"; then
        BUS_TYPE="i2c"
    elif echo "$BUS_PATH" | grep -qi "MSFT"; then
        BUS_TYPE="ftpm"
    elif echo "$BUS_PATH" | grep -qi "PNP"; then
        BUS_TYPE="lpc"
    fi
fi

# Description from sysfs
TPM_DESC=""
[ -f /sys/class/tpm/tpm0/device/description ] && TPM_DESC=$(cat /sys/class/tpm/tpm0/device/description 2>/dev/null || echo "")

# ─────────────────────────────────────────────────────────────────────────────
# Collect Capabilities
# ─────────────────────────────────────────────────────────────────────────────

# Max key sizes
MAX_RSA_BYTES=$(get_prop "TPM2_PT_MAX_RSA_KEY_BYTES")
MAX_RSA_BITS=""
[ -n "$MAX_RSA_BYTES" ] && MAX_RSA_BITS=$((0x$MAX_RSA_BYTES * 8))

MAX_ECC=$(get_prop "TPM2_PT_MAX_ECC_KEY_BYTES")
MAX_ECC_BITS=""
[ -n "$MAX_ECC" ] && MAX_ECC_BITS=$((0x$MAX_ECC * 8))

# Algorithms (remove trailing colons)
ALGS_RAW=$(tpm2_getcap algorithms 2>/dev/null | grep -E "^\s*(rsa|ecc|aes|sha|hmac|mgf1|kdf|oaep|ecdsa|ecdh|ecmqv|sm|camellia|cmac|cbc|cfb|ecb|ofb|ctr|xor)" | awk '{print $1}' | sed 's/:$//' | sort -u)
ALGS_JSON=$(echo "$ALGS_RAW" | while read alg; do [ -n "$alg" ] && printf '"%s",' "$alg"; done | sed 's/,$//')

# PCR banks
PCR_BANKS_RAW=$(tpm2_getcap pcrs 2>/dev/null | grep "bank:" | sed 's/.*bank: //')
PCR_BANKS_JSON=$(echo "$PCR_BANKS_RAW" | while read bank; do [ -n "$bank" ] && printf '"%s",' "$bank"; done | sed 's/,$//')

# ─────────────────────────────────────────────────────────────────────────────
# Collect Ownership/Authorization Status
# ─────────────────────────────────────────────────────────────────────────────

PROPS_VAR=$(tpm2_getcap properties-variable 2>/dev/null || echo "")

get_var_prop() {
    echo "$PROPS_VAR" | grep -A1 "$1" | tail -1 | awk '{print $2}'
}

OWNER_AUTH_SET=$(get_var_prop "TPM2_PT_PERSISTENT" | grep -q "ownerAuthSet" && echo "true" || echo "false")
# Check individual auth flags
OWNER_AUTH=$(echo "$PROPS_VAR" | grep -A5 "TPM2_PT_PERSISTENT" | grep -q "ownerAuthSet" && echo "true" || echo "false")
ENDORSEMENT_AUTH=$(echo "$PROPS_VAR" | grep -A5 "TPM2_PT_PERSISTENT" | grep -q "endorsementAuthSet" && echo "true" || echo "false")
LOCKOUT_AUTH=$(echo "$PROPS_VAR" | grep -A5 "TPM2_PT_PERSISTENT" | grep -q "lockoutAuthSet" && echo "true" || echo "false")

# Lockout status (convert hex to decimal)
LOCKOUT_COUNTER_HEX=$(get_var_prop "TPM2_PT_LOCKOUT_COUNTER")
MAX_AUTH_FAIL_HEX=$(get_var_prop "TPM2_PT_MAX_AUTH_FAIL")
LOCKOUT_INTERVAL_HEX=$(get_var_prop "TPM2_PT_LOCKOUT_INTERVAL")
LOCKOUT_RECOVERY_HEX=$(get_var_prop "TPM2_PT_LOCKOUT_RECOVERY")

LOCKOUT_COUNTER=0
MAX_AUTH_FAIL=""
LOCKOUT_INTERVAL=""
LOCKOUT_RECOVERY=""
[ -n "$LOCKOUT_COUNTER_HEX" ] && LOCKOUT_COUNTER=$((LOCKOUT_COUNTER_HEX))
[ -n "$MAX_AUTH_FAIL_HEX" ] && MAX_AUTH_FAIL=$((MAX_AUTH_FAIL_HEX))
[ -n "$LOCKOUT_INTERVAL_HEX" ] && LOCKOUT_INTERVAL=$((LOCKOUT_INTERVAL_HEX))
[ -n "$LOCKOUT_RECOVERY_HEX" ] && LOCKOUT_RECOVERY=$((LOCKOUT_RECOVERY_HEX))

# In lockout?
IN_LOCKOUT="false"
[ "$LOCKOUT_COUNTER" -gt 0 ] 2>/dev/null && IN_LOCKOUT="true"

# ─────────────────────────────────────────────────────────────────────────────
# Collect Clock/Uptime Info
# ─────────────────────────────────────────────────────────────────────────────

CLOCK_INFO=$(tpm2_readclock 2>/dev/null || echo "")
TPM_TIME=""
TPM_CLOCK=""
TPM_RESETS=""
TPM_RESTARTS=""
if [ -n "$CLOCK_INFO" ]; then
    TPM_TIME=$(echo "$CLOCK_INFO" | grep "time:" | awk '{print $2}')
    TPM_CLOCK=$(echo "$CLOCK_INFO" | grep "clock:" | awk '{print $2}')
    TPM_RESETS=$(echo "$CLOCK_INFO" | grep "reset_count:" | awk '{print $2}')
    TPM_RESTARTS=$(echo "$CLOCK_INFO" | grep "restart_count:" | awk '{print $2}')
fi

# ─────────────────────────────────────────────────────────────────────────────
# Collect Persistent Keys
# ─────────────────────────────────────────────────────────────────────────────

HANDLES_RAW=$(tpm2_getcap handles-persistent 2>/dev/null | grep "0x" | tr -d ' -')
KEYS_JSON=""

for handle in $HANDLES_RAW; do
    INFO=$(tpm2_readpublic -c $handle 2>/dev/null || echo "")
    if [ -n "$INFO" ]; then
        # Type and name-alg have "value:" on the next line
        TYPE=$(echo "$INFO" | grep -A1 "^type:" | grep "value:" | sed 's/.*value: //')
        BITS=$(echo "$INFO" | grep "^bits:" | awk '{print $2}')
        NAME_ALG=$(echo "$INFO" | grep -A1 "^name-alg:" | grep "value:" | sed 's/.*value: //')
        ATTRS=$(echo "$INFO" | grep -A1 "^attributes:" | grep "value:" | sed 's/.*value: //')

        # RSA-specific: exponent
        EXPONENT=$(echo "$INFO" | grep "^exponent:" | awk '{print $2}')

        # Scheme info
        SCHEME=$(echo "$INFO" | grep -A1 "^scheme:" | grep "value:" | sed 's/.*value: //')

        # Policy digest (indicates if key has authorization policy, e.g., PCR binding)
        POLICY_DIGEST=$(echo "$INFO" | grep "^authorization policy:" | awk '{print $3}')
        HAS_POLICY="false"
        # Non-zero policy digest means key has a policy
        if [ -n "$POLICY_DIGEST" ] && [ "$POLICY_DIGEST" != "0000000000000000000000000000000000000000000000000000000000000000" ]; then
            HAS_POLICY="true"
        fi

        # Parse attributes into array
        ATTRS_JSON=$(echo "$ATTRS" | tr '|' '\n' | while read attr; do
            [ -n "$attr" ] && printf '"%s",' "$attr"
        done | sed 's/,$//')

        IS_KEYVAULT="false"
        [ "$handle" = "0x81010002" ] && IS_KEYVAULT="true"

        KEYS_JSON="${KEYS_JSON}{\"handle\":\"$handle\",\"type\":\"$TYPE\",\"bits\":${BITS:-null},\"name_alg\":\"$NAME_ALG\",\"exponent\":${EXPONENT:-null},\"scheme\":$([ -n "$SCHEME" ] && echo "\"$SCHEME\"" || echo "null"),\"has_policy\":$HAS_POLICY,\"policy_digest\":$([ -n "$POLICY_DIGEST" ] && echo "\"$POLICY_DIGEST\"" || echo "null"),\"attributes\":[${ATTRS_JSON}],\"is_keyvault\":$IS_KEYVAULT},"
    fi
done
KEYS_JSON=$(echo "$KEYS_JSON" | sed 's/,$//')

# ─────────────────────────────────────────────────────────────────────────────
# Collect PCR Values (commonly used PCRs)
# ─────────────────────────────────────────────────────────────────────────────

PCR_VALUES_JSON=""
PCR_RAW=$(tpm2_pcrread sha256:0,1,7,14,15,16 2>/dev/null || echo "")
if [ -n "$PCR_RAW" ]; then
    # Parse PCR values - format is "    N : 0xHASH"
    while IFS= read -r line; do
        if echo "$line" | grep -qE "^\s+[0-9]+\s*:"; then
            PCR_NUM=$(echo "$line" | sed 's/^\s*//' | cut -d: -f1 | tr -d ' ')
            PCR_VAL=$(echo "$line" | cut -d: -f2 | tr -d ' ')
            # Check if PCR is zero (all zeros)
            IS_ZERO="false"
            if echo "$PCR_VAL" | grep -qE "^0x0+$"; then
                IS_ZERO="true"
            fi
            PCR_VALUES_JSON="${PCR_VALUES_JSON}{\"index\":$PCR_NUM,\"value\":\"$PCR_VAL\",\"is_zero\":$IS_ZERO},"
        fi
    done <<< "$PCR_RAW"
    PCR_VALUES_JSON=$(echo "$PCR_VALUES_JSON" | sed 's/,$//')
fi

# ─────────────────────────────────────────────────────────────────────────────
# Collect Transient/Session Info
# ─────────────────────────────────────────────────────────────────────────────

TRANSIENT_COUNT=$(tpm2_getcap handles-transient 2>/dev/null | grep -c "0x") || TRANSIENT_COUNT=0
SESSION_COUNT=$(tpm2_getcap handles-loaded-session 2>/dev/null | grep -c "0x") || SESSION_COUNT=0
SAVED_SESSION_COUNT=$(tpm2_getcap handles-saved-session 2>/dev/null | grep -c "0x") || SAVED_SESSION_COUNT=0

# ─────────────────────────────────────────────────────────────────────────────
# Collect Local Key Files
# ─────────────────────────────────────────────────────────────────────────────

FILES_JSON=""
if [ -d "keys" ]; then
    for f in keys/*; do
        if [ -f "$f" ]; then
            NAME=$(basename "$f")
            SIZE=$(stat --format=%s "$f" 2>/dev/null || echo "0")
            PERMS=$(stat --format=%a "$f" 2>/dev/null || echo "000")
            MODIFIED=$(stat --format=%Y "$f" 2>/dev/null || echo "0")

            # Determine file type
            FTYPE="unknown"
            case "$NAME" in
                *.pem) FTYPE="public_key" ;;
                *.ctx) FTYPE="context" ;;
                *.priv) FTYPE="encrypted_private" ;;
                *.pub) FTYPE="tpm_public" ;;
                pcr_policy) FTYPE="pcr_config" ;;
                pcr_value) FTYPE="pcr_value" ;;
            esac

            FILES_JSON="${FILES_JSON}{\"name\":\"$NAME\",\"size\":$SIZE,\"permissions\":\"$PERMS\",\"modified\":$MODIFIED,\"type\":\"$FTYPE\"},"
        fi
    done
    FILES_JSON=$(echo "$FILES_JSON" | sed 's/,$//')
fi

# ─────────────────────────────────────────────────────────────────────────────
# Collect PCR Policy Config
# ─────────────────────────────────────────────────────────────────────────────

PCR_POLICY_INDEX=""
PCR_POLICY_VALUE=""
if [ -f "keys/pcr_policy" ]; then
    PCR_POLICY_INDEX=$(cat keys/pcr_policy 2>/dev/null || echo "")
fi
if [ -f "keys/pcr_value" ]; then
    PCR_POLICY_VALUE=$(cat keys/pcr_value 2>/dev/null || echo "")
fi

# ─────────────────────────────────────────────────────────────────────────────
# Health Checks
# ─────────────────────────────────────────────────────────────────────────────

RNG_OK="false"
RNG_SAMPLE=""
if RANDOM_HEX=$(tpm2_getrandom 8 --hex 2>/dev/null); then
    RNG_OK="true"
    RNG_SAMPLE="$RANDOM_HEX"
fi

KEYVAULT_OK="false"
tpm2_readpublic -c 0x81010002 &>/dev/null && KEYVAULT_OK="true"

PERMISSIONS_OK="false"
[ -r /dev/tpmrm0 ] && [ -w /dev/tpmrm0 ] && PERMISSIONS_OK="true"

ABRMD_RUNNING="false"
systemctl is-active tpm2-abrmd &>/dev/null && ABRMD_RUNNING="true"

# ─────────────────────────────────────────────────────────────────────────────
# Build JSON Output
# ─────────────────────────────────────────────────────────────────────────────

JSON=$(cat <<EOF
{
  "timestamp": $(date +%s),
  "device": {
    "tpm0_available": $DEVICE_TPM0,
    "tpmrm0_available": $DEVICE_TPMRM0,
    "bus_type": "$BUS_TYPE",
    "description": $(json_escape "$TPM_DESC")
  },
  "info": {
    "manufacturer": $(json_escape "$MANUFACTURER"),
    "vendor_string": $(json_escape "$VENDOR_STRING"),
    "firmware_version": $([ -n "$FW_VERSION" ] && echo "\"$FW_VERSION\"" || echo "null"),
    "spec_version": $([ -n "$SPEC_VERSION" ] && echo "\"$SPEC_VERSION\"" || echo "null"),
    "spec_level": $([ -n "$SPEC_LEVEL" ] && echo "$SPEC_LEVEL" || echo "null"),
    "manufacture_year": $([ -n "$YEAR" ] && echo "$YEAR" || echo "null"),
    "manufacture_day": $([ -n "$DAY" ] && echo "$DAY" || echo "null")
  },
  "capabilities": {
    "max_rsa_bits": $([ -n "$MAX_RSA_BITS" ] && echo "$MAX_RSA_BITS" || echo "null"),
    "max_ecc_bits": $([ -n "$MAX_ECC_BITS" ] && echo "$MAX_ECC_BITS" || echo "null"),
    "algorithms": [${ALGS_JSON}],
    "pcr_banks": [${PCR_BANKS_JSON}]
  },
  "authorization": {
    "owner_auth_set": $OWNER_AUTH,
    "endorsement_auth_set": $ENDORSEMENT_AUTH,
    "lockout_auth_set": $LOCKOUT_AUTH,
    "in_lockout": $IN_LOCKOUT,
    "lockout_counter": ${LOCKOUT_COUNTER:-0},
    "max_auth_failures": $([ -n "$MAX_AUTH_FAIL" ] && echo "$MAX_AUTH_FAIL" || echo "null"),
    "lockout_interval_seconds": $([ -n "$LOCKOUT_INTERVAL" ] && echo "$LOCKOUT_INTERVAL" || echo "null"),
    "lockout_recovery_seconds": $([ -n "$LOCKOUT_RECOVERY" ] && echo "$LOCKOUT_RECOVERY" || echo "null")
  },
  "clock": {
    "uptime_ms": $([ -n "$TPM_TIME" ] && echo "$TPM_TIME" || echo "null"),
    "clock_ms": $([ -n "$TPM_CLOCK" ] && echo "$TPM_CLOCK" || echo "null"),
    "reset_count": $([ -n "$TPM_RESETS" ] && echo "$TPM_RESETS" || echo "null"),
    "restart_count": $([ -n "$TPM_RESTARTS" ] && echo "$TPM_RESTARTS" || echo "null")
  },
  "persistent_keys": [${KEYS_JSON}],
  "pcr_values": [${PCR_VALUES_JSON}],
  "sessions": {
    "transient_objects": $TRANSIENT_COUNT,
    "loaded_sessions": $SESSION_COUNT,
    "saved_sessions": $SAVED_SESSION_COUNT
  },
  "keyvault": {
    "key_provisioned": $KEYVAULT_OK,
    "key_handle": "0x81010002",
    "pcr_policy_enabled": $([ -n "$PCR_POLICY_INDEX" ] && echo "true" || echo "false"),
    "pcr_policy_index": $([ -n "$PCR_POLICY_INDEX" ] && echo "$PCR_POLICY_INDEX" || echo "null"),
    "pcr_policy_value": $([ -n "$PCR_POLICY_VALUE" ] && json_escape "$PCR_POLICY_VALUE" || echo "null"),
    "local_files": [${FILES_JSON}]
  },
  "health": {
    "rng_working": $RNG_OK,
    "rng_sample": $([ -n "$RNG_SAMPLE" ] && echo "\"$RNG_SAMPLE\"" || echo "null"),
    "keyvault_accessible": $KEYVAULT_OK,
    "device_permissions_ok": $PERMISSIONS_OK,
    "abrmd_running": $ABRMD_RUNNING
  }
}
EOF
)

# Output
if [ "$PRETTY" = true ]; then
    echo "$JSON" | python3 -m json.tool 2>/dev/null || echo "$JSON"
else
    # Compact: remove extra whitespace
    echo "$JSON" | tr -d '\n' | sed 's/  */ /g'
fi
