#!/bin/bash
#
# tpm2_status.sh - Display TPM2 chip status and key inventory
#

set -e

# Colors (optional, disable with NO_COLOR=1)
if [ -z "$NO_COLOR" ] && [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    NC='\033[0m' # No Color
else
    RED='' GREEN='' YELLOW='' BLUE='' PURPLE='' CYAN='' NC=''
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                            TPM2 STATUS REPORT                                 ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1: Device Info
# ─────────────────────────────────────────────────────────────────────────────
echo "┌─────────────────────────────────────────────────────────────────────────────┐"
echo "│  DEVICE INFORMATION                                                         │"
echo "├─────────────────────────────────────────────────────────────────────────────┤"

# Check device exists
if [ -c /dev/tpm0 ]; then
    echo -e "│  Device:        ${GREEN}/dev/tpm0${NC} (direct access)"
else
    echo -e "│  Device:        ${RED}/dev/tpm0 NOT FOUND${NC}"
fi

if [ -c /dev/tpmrm0 ]; then
    echo -e "│  Resource Mgr:  ${GREEN}/dev/tpmrm0${NC} (kernel managed) ← recommended"
else
    echo -e "│  Resource Mgr:  ${YELLOW}/dev/tpmrm0 NOT FOUND${NC}"
fi

# Manufacturer info
MANUFACTURER=$(tpm2_getcap properties-fixed 2>/dev/null | grep -A1 "TPM2_PT_MANUFACTURER" | tail -1 | awk '{print $2}' | xxd -r -p 2>/dev/null || echo "unknown")
VENDOR1=$(tpm2_getcap properties-fixed 2>/dev/null | grep -A1 "TPM2_PT_VENDOR_STRING_1" | tail -1 | awk '{print $2}' | xxd -r -p 2>/dev/null || echo "")
VENDOR2=$(tpm2_getcap properties-fixed 2>/dev/null | grep -A1 "TPM2_PT_VENDOR_STRING_2" | tail -1 | awk '{print $2}' | xxd -r -p 2>/dev/null || echo "")
FW_V1=$(tpm2_getcap properties-fixed 2>/dev/null | grep -A1 "TPM2_PT_FIRMWARE_VERSION_1" | tail -1 | awk '{print $2}' || echo "0")
FW_V2=$(tpm2_getcap properties-fixed 2>/dev/null | grep -A1 "TPM2_PT_FIRMWARE_VERSION_2" | tail -1 | awk '{print $2}' || echo "0")

echo "│  Manufacturer:  ${MANUFACTURER}${VENDOR1}${VENDOR2}"

# Firmware version (convert hex to readable)
if [ -n "$FW_V1" ] && [ "$FW_V1" != "0" ]; then
    # Remove 0x prefix if present, handle parsing errors gracefully
    FW_V1_CLEAN=$(echo "$FW_V1" | sed 's/^0x//')
    FW_MAJOR=$(printf "%d" $((16#${FW_V1_CLEAN:0:4})) 2>/dev/null || echo "?")
    FW_MINOR=$(printf "%d" $((16#${FW_V1_CLEAN:4:4})) 2>/dev/null || echo "?")
    echo "│  Firmware:      ${FW_MAJOR}.${FW_MINOR}"
fi

# TPM Type (discrete vs firmware)
if [ -f /sys/class/tpm/tpm0/device/description ]; then
    TPM_DESC=$(cat /sys/class/tpm/tpm0/device/description 2>/dev/null || echo "unknown")
    echo "│  Description:   ${TPM_DESC}"
fi

# Bus type
if [ -d /sys/class/tpm/tpm0/device ]; then
    BUS_PATH=$(readlink -f /sys/class/tpm/tpm0/device 2>/dev/null || echo "")
    if echo "$BUS_PATH" | grep -q "spi"; then
        echo -e "│  Bus:           ${YELLOW}SPI${NC} (physical bus - use encrypted sessions!)"
    elif echo "$BUS_PATH" | grep -q "i2c"; then
        echo -e "│  Bus:           ${YELLOW}I2C${NC} (physical bus - use encrypted sessions!)"
    elif echo "$BUS_PATH" | grep -q "MSFT"; then
        echo -e "│  Bus:           ${GREEN}Firmware TPM (fTPM)${NC} - internal to CPU"
    elif echo "$BUS_PATH" | grep -q "PNP"; then
        echo -e "│  Bus:           ${CYAN}LPC${NC} (Low Pin Count)"
    else
        echo "│  Bus:           $(basename $(dirname $BUS_PATH) 2>/dev/null || echo 'unknown')"
    fi
fi

echo "└─────────────────────────────────────────────────────────────────────────────┘"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2: Capabilities
# ─────────────────────────────────────────────────────────────────────────────
echo "┌─────────────────────────────────────────────────────────────────────────────┐"
echo "│  CAPABILITIES                                                               │"
echo "├─────────────────────────────────────────────────────────────────────────────┤"

# Supported algorithms
ALGS=$(tpm2_getcap algorithms 2>/dev/null | grep -E "^\s*(rsa|ecc|aes|sha)" | awk '{print $1}' | tr '\n' ' ' | head -c 60)
echo "│  Algorithms:    ${ALGS:-unknown}"

# Max RSA key size
MAX_RSA=$(tpm2_getcap properties-fixed 2>/dev/null | grep -A1 "TPM2_PT_MAX_RSA_KEY_BYTES" | tail -1 | awk '{print $2}')
if [ -n "$MAX_RSA" ]; then
    MAX_RSA_BITS=$((0x$MAX_RSA * 8))
    echo "│  Max RSA:       ${MAX_RSA_BITS} bits"
fi

# PCR banks
PCR_BANKS=$(tpm2_getcap pcrs 2>/dev/null | grep "bank" | sed 's/.*bank: //' | tr '\n' ' ')
echo "│  PCR Banks:     ${PCR_BANKS:-unknown}"

echo "└─────────────────────────────────────────────────────────────────────────────┘"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3: Persistent Keys
# ─────────────────────────────────────────────────────────────────────────────
echo "┌─────────────────────────────────────────────────────────────────────────────┐"
echo "│  PERSISTENT KEYS (NV Storage)                                               │"
echo "├─────────────────────────────────────────────────────────────────────────────┤"

HANDLES=$(tpm2_getcap handles-persistent 2>/dev/null | grep "0x" | tr -d ' -')

if [ -z "$HANDLES" ]; then
    echo "│  (no persistent keys found)                                                 │"
else
    printf "│  %-14s │ %-7s │ %-10s │ %-26s │\n" "Handle" "Type" "Bits" "Attributes"
    echo "│  ────────────────────────────────────────────────────────────────────────── │"

    for handle in $HANDLES; do
        INFO=$(tpm2_readpublic -c $handle 2>/dev/null)
        TYPE=$(echo "$INFO" | grep -A1 "^type:" | tail -1 | sed 's/.*value: //')
        BITS=$(echo "$INFO" | grep "^bits:" | awk '{print $2}')
        ATTRS=$(echo "$INFO" | grep -A1 "^attributes:" | tail -1 | sed 's/.*value: //' | cut -c1-26)

        if [ "$handle" = "0x81010002" ]; then
            printf "│  ${GREEN}%-14s${NC} │ %-7s │ %-10s │ %-26s │ ${CYAN}← KeyVault${NC}\n" "$handle" "$TYPE" "$BITS" "$ATTRS"
        else
            printf "│  %-14s │ %-7s │ %-10s │ %-26s │\n" "$handle" "$TYPE" "$BITS" "$ATTRS"
        fi
    done
fi

echo "└─────────────────────────────────────────────────────────────────────────────┘"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4: Transient Objects
# ─────────────────────────────────────────────────────────────────────────────
echo "┌─────────────────────────────────────────────────────────────────────────────┐"
echo "│  TRANSIENT OBJECTS (Session Memory)                                         │"
echo "├─────────────────────────────────────────────────────────────────────────────┤"

TRANSIENT=$(tpm2_getcap handles-transient 2>/dev/null | grep "0x" | wc -l)
SESSIONS=$(tpm2_getcap handles-loaded-session 2>/dev/null | grep "0x" | wc -l)
SAVED_SESSIONS=$(tpm2_getcap handles-saved-session 2>/dev/null | grep "0x" | wc -l)

echo "│  Loaded keys:      ${TRANSIENT}"
echo "│  Active sessions:  ${SESSIONS}"
echo "│  Saved sessions:   ${SAVED_SESSIONS}"

echo "└─────────────────────────────────────────────────────────────────────────────┘"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5: Local Key Files
# ─────────────────────────────────────────────────────────────────────────────
if [ -d "keys" ]; then
    echo "┌─────────────────────────────────────────────────────────────────────────────┐"
    echo "│  LOCAL KEY FILES (./keys/)                                                  │"
    echo "├─────────────────────────────────────────────────────────────────────────────┤"

    for f in keys/*; do
        if [ -f "$f" ]; then
            SIZE=$(stat --format=%s "$f" 2>/dev/null || echo "?")
            NAME=$(basename "$f")
            PERMS=$(stat --format=%a "$f" 2>/dev/null || echo "???")

            # Color based on file type
            case "$NAME" in
                *.pem)
                    printf "│    %-28s %8s bytes  [%s]  ${GREEN}public key${NC}\n" "$NAME" "$SIZE" "$PERMS"
                    ;;
                *.ctx)
                    printf "│    %-28s %8s bytes  [%s]  ${PURPLE}context${NC}\n" "$NAME" "$SIZE" "$PERMS"
                    ;;
                *.priv)
                    printf "│    %-28s %8s bytes  [%s]  ${YELLOW}encrypted private${NC}\n" "$NAME" "$SIZE" "$PERMS"
                    ;;
                *.pub)
                    printf "│    %-28s %8s bytes  [%s]  ${CYAN}TPM public${NC}\n" "$NAME" "$SIZE" "$PERMS"
                    ;;
                *)
                    printf "│    %-28s %8s bytes  [%s]\n" "$NAME" "$SIZE" "$PERMS"
                    ;;
            esac
        fi
    done

    echo "└─────────────────────────────────────────────────────────────────────────────┘"
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6: Quick Health Check
# ─────────────────────────────────────────────────────────────────────────────
echo "┌─────────────────────────────────────────────────────────────────────────────┐"
echo "│  HEALTH CHECK                                                               │"
echo "├─────────────────────────────────────────────────────────────────────────────┤"

# Test random number generation
if RANDOM_HEX=$(tpm2_getrandom 8 --hex 2>/dev/null); then
    echo -e "│  RNG Test:      ${GREEN}OK${NC} (got: ${RANDOM_HEX})"
else
    echo -e "│  RNG Test:      ${RED}FAILED${NC}"
fi

# Check if our key exists
if tpm2_readpublic -c 0x81010002 &>/dev/null; then
    echo -e "│  KeyVault Key:  ${GREEN}OK${NC} (0x81010002 exists)"
else
    echo -e "│  KeyVault Key:  ${YELLOW}NOT FOUND${NC} (run: bash init.sh)"
fi

# Check user permissions
if [ -r /dev/tpmrm0 ] && [ -w /dev/tpmrm0 ]; then
    echo -e "│  Permissions:   ${GREEN}OK${NC} (read/write access to /dev/tpmrm0)"
else
    echo -e "│  Permissions:   ${RED}DENIED${NC} (add user to 'tss' group)"
fi

# Check if tpm2-abrmd is running (optional)
if systemctl is-active tpm2-abrmd &>/dev/null; then
    echo -e "│  tpm2-abrmd:    ${CYAN}RUNNING${NC} (user-space resource manager)"
else
    echo -e "│  tpm2-abrmd:    ${NC}not running (using kernel RM - OK)"
fi

echo "└─────────────────────────────────────────────────────────────────────────────┘"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7: ASCII Diagram
# ─────────────────────────────────────────────────────────────────────────────
echo "┌─────────────────────────────────────────────────────────────────────────────┐"
echo "│  TPM KEY HIERARCHY                                                          │"
echo "├─────────────────────────────────────────────────────────────────────────────┤"
echo "│                                                                             │"
echo "│      ┌─────────────────────────────────────────────────────────┐            │"
echo "│      │              TPM2 CHIP (Silicon)                        │            │"
echo "│      │                                                         │            │"
echo "│      │   ┌─────────────────────────────────────────────────┐   │            │"
echo "│      │   │        SEED (burned in manufacturing)           │   │            │"
echo "│      │   └─────────────────────┬───────────────────────────┘   │            │"
echo "│      │                         │                               │            │"
echo "│      │           ┌─────────────┼─────────────┐                 │            │"
echo "│      │           ▼             ▼             ▼                 │            │"
echo "│      │      ┌────────┐   ┌──────────┐   ┌──────────┐           │            │"
echo "│      │      │ OWNER  │   │ENDORSEMT │   │ PLATFORM │           │            │"
echo "│      │      └───┬────┘   └────┬─────┘   └──────────┘           │            │"
echo "│      │          │             │                                │            │"
echo "│      │          ▼             ▼                                │            │"
echo "│      │     ┌─────────┐  ┌──────────┐                           │            │"
echo "│      │     │ Primary │  │    EK    │ ← session salting         │            │"
echo "│      │     └────┬────┘  └──────────┘                           │            │"
echo "│      │          │                                              │            │"
echo "│      │          ▼            NV STORAGE                        │            │"
echo "│      │   ╔════════════════════════════════════════════╗        │            │"

# Show persistent handles in diagram
for handle in $HANDLES; do
    if [ "$handle" = "0x81010002" ]; then
        echo "│      │   ║  ${handle}  RSA-2048 (KeyVault)     ║        │            │"
    fi
done

echo "│      │   ╚════════════════════════════════════════════╝        │            │"
echo "│      │                                                         │            │"
echo "│      └─────────────────────────────────────────────────────────┘            │"
echo "│                                                                             │"
echo "└─────────────────────────────────────────────────────────────────────────────┘"
echo ""
