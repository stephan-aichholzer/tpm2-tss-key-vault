# PCR Policy - Platform Binding for TPM Keys

This document explains how PCR (Platform Configuration Register) policies work
and how to use them to bind TPM keys to specific device identities.

## Overview

PCR policies allow you to bind a TPM key to the platform state. The key will
**only work** when the specified PCR contains the expected value. This is
enforced by the TPM hardware - there is no software bypass.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  WITHOUT PCR Policy:                                                    │
│    - Key works on any system that has the TPM                          │
│    - If TPM module is moved to another device, key still works         │
│                                                                         │
│  WITH PCR Policy:                                                       │
│    - Key bound to specific PCR value                                   │
│    - If TPM moved to another device with different PCR → KEY FAILS     │
│    - Hardware-enforced, cannot be bypassed in software                 │
└─────────────────────────────────────────────────────────────────────────┘
```

## Use Case: Removable TPM Modules

For platforms with removable TPM modules (e.g., Raspberry Pi with SPI TPM),
an attacker could theoretically:

1. Steal the TPM module
2. Install it on their own device
3. Use the keys stored in the TPM

PCR policy prevents this by binding the key to a device-specific identity
(serial number, MAC address, etc.) that differs between devices.

## How PCR Works

### PCR Extend Operation

PCRs are not simply "set" to a value. They are **extended** using a
cryptographic chain:

```
PCR_new = SHA256(PCR_old || measurement)

Example:
  PCR starts at:     0x0000000000000000...
  Extend with hash:  SHA256("SERIAL-001") = 0xABC123...
  PCR becomes:       SHA256(0x000... || 0xABC123...) = 0xDEF456...
```

This chaining means:
- Order of extensions matters
- Extensions cannot be undone
- Only a reset (reboot) returns PCR to zero

### PCR Types

```
┌────────┬──────────────────┬─────────────────┬─────────────────────────┐
│  PCR   │  Hardware Reset  │  Software Reset │  Recommended Use        │
├────────┼──────────────────┼─────────────────┼─────────────────────────┤
│  0-15  │       Yes        │       No        │  Production             │
│  16    │       Yes        │       Yes       │  Development/Testing    │
│  17-23 │       Yes        │    (varies)     │  OS/Application         │
└────────┴──────────────────┴─────────────────┴─────────────────────────┘

PCR 14-15: Best for production IoT devices
PCR 16:    Debug PCR, can reset without reboot (for testing)
```

## Production Workflow

### Factory Provisioning

```
┌─────────────────────────────────────────────────────────────────────────┐
│  FACTORY / PRODUCTION LINE                                              │
│                                                                         │
│  1. Device boots fresh (PCRs = 0x000...)                               │
│                                                                         │
│  2. Read device serial number from EEPROM/efuse                        │
│     SERIAL="DEVICE-001-2024-FACTORY-A"                                 │
│                                                                         │
│  3. Run provisioning:                                                   │
│     ./scripts/init.sh --pcr 14 --pcr-value "$SERIAL"                   │
│                                                                         │
│     This does:                                                          │
│       a) Extend PCR 14 with SHA256(SERIAL)                             │
│       b) Create TPM key with policy "PCR 14 must match"                │
│       c) Save SERIAL to keys/pcr_value for boot script                 │
│                                                                         │
│  4. Device shipped to customer                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Customer Device Boot

```
┌─────────────────────────────────────────────────────────────────────────┐
│  CUSTOMER DEVICE (every boot)                                           │
│                                                                         │
│  1. Device boots (PCRs reset to 0x000...)                              │
│                                                                         │
│  2. Early boot script runs (systemd service / init.d):                 │
│     ./scripts/pcr.sh boot                                               │
│                                                                         │
│     This reads keys/pcr_value and extends PCR with saved value         │
│                                                                         │
│  3. PCR now matches the value from provisioning                        │
│                                                                         │
│  4. Application starts, uses TPM key                                    │
│     - TPM checks: "Does PCR 14 match policy?"                          │
│     - Yes → Key operation allowed                                       │
│     - No  → TPM2_RC_POLICY_FAIL                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### Attack Scenario (Defeated)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ATTACKER steals TPM module, installs on their device                   │
│                                                                         │
│  1. Attacker boots their device (PCRs = 0x000...)                      │
│                                                                         │
│  2. Attacker doesn't know the original SERIAL value                    │
│     - Even if they guess, their device has different characteristics   │
│                                                                         │
│  3. Attacker tries to use the key:                                      │
│     - TPM checks PCR 14                                                │
│     - PCR 14 ≠ expected value                                          │
│     - TPM refuses: TPM2_RC_POLICY_FAIL                                 │
│                                                                         │
│  4. Key is USELESS on the attacker's device                            │
└─────────────────────────────────────────────────────────────────────────┘
```

## Demo Workflow (PCR 16)

For development and testing, use PCR 16 which can be reset without rebooting:

```bash
# 1. Clear any existing key
./scripts/clear.sh

# 2. Provision with PCR 16 policy
./scripts/init.sh --pcr 16 --pcr-value "DEMO-SERIAL-001"

# 3. Test that key works
./source/build/key_vault_example    # Should work

# 4. Simulate "reboot" (reset PCR)
./scripts/pcr.sh reset 16

# 5. Extend with WRONG value (simulate different device)
./scripts/pcr.sh extend 16 "WRONG-SERIAL"

# 6. Try to use key - SHOULD FAIL
./source/build/key_vault_example    # TPM2_RC_POLICY_FAIL

# 7. Reset and extend with correct value
./scripts/pcr.sh reset 16
./scripts/pcr.sh extend 16 "DEMO-SERIAL-001"

# 8. Key works again
./source/build/key_vault_example    # Should work
```

## Scripts Reference

All scripts are in the `scripts/` directory.

### init.sh

Main provisioning script with PCR policy support:

```bash
# Without PCR policy (backward compatible)
./scripts/init.sh

# With PCR policy
./scripts/init.sh --pcr 16 --pcr-value "DEVICE-SERIAL"
./scripts/init.sh --pcr 14 --pcr-value "DEVICE-SERIAL"  # Production
```

### pcr.sh

PCR management tool:

```bash
./scripts/pcr.sh read              # Show common PCR values
./scripts/pcr.sh read 16           # Show specific PCR
./scripts/pcr.sh extend 16 "value" # Extend PCR with value
./scripts/pcr.sh reset 16          # Reset PCR 16 (debug only)
./scripts/pcr.sh boot              # Boot-time: restore from config
```

### list.sh

Show TPM persistent handles:

```bash
./scripts/list.sh
```

### clear.sh

Remove KeyVault key and config:

```bash
./scripts/clear.sh
./scripts/clear.sh --force         # Skip safety checks
```

## Files

After provisioning with PCR policy, these files are created:

```
keys/
├── tpm_rsa_pub.pem    # Public key (for encryption)
├── ek.ctx             # Endorsement Key context (for sessions)
├── ek.pub             # Endorsement Key public part
├── pcr_policy         # PCR number (e.g., "16")
└── pcr_value          # Identity value (e.g., "DEVICE-SERIAL")
```

The `pcr_value` file is used by the boot script (`./scripts/pcr.sh boot`) to restore
the PCR to the correct value on each boot.

## C++ Integration

When a PCR policy is configured, the KeyVault C++ code must use a **policy
session** instead of a password session when accessing the key:

```cpp
// Without PCR policy:
Esys_RSA_Decrypt(ctx, key_handle,
    ESYS_TR_PASSWORD,  // Password session
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    ...);

// With PCR policy:
// 1. Start policy session
Esys_StartAuthSession(..., TPM2_SE_POLICY, ...);

// 2. Satisfy PCR policy
Esys_PolicyPCR(ctx, session, ...);

// 3. Use policy session for operation
Esys_RSA_Decrypt(ctx, key_handle,
    policy_session,    // Policy session (not password)
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    ...);
```

The TPM will check that the current PCR value matches what was recorded in
the key's policy during creation. If it doesn't match, the operation fails.

## Security Considerations

### What PCR Policy Protects Against

- **TPM module theft**: Key unusable on different platform
- **Platform substitution**: Attacker can't use their own hardware
- **Boot tampering**: If using PCRs 0-7, measures boot chain integrity

### What PCR Policy Does NOT Protect Against

- **Full device theft**: If attacker has entire device (not just TPM)
- **Runtime attacks**: Once key is loaded, memory can be attacked
- **Side-channel attacks**: Physical attacks on the TPM itself

### Best Practices

1. **Use PCR 14 or 15 for production** - Cannot be reset by software
2. **Combine multiple measurements** - Serial + MAC + firmware hash
3. **Use EK-salted sessions** - Encrypt TPM bus communication
4. **Add process hardening** - Anti-debug, memory locking
5. **Physical security** - Tamper-evident enclosures

## Troubleshooting

### Key operation fails with policy error

```
Error: TPM2_RC_POLICY_FAIL
```

The PCR value doesn't match the policy. Solutions:
1. Run `./scripts/pcr.sh boot` to restore correct PCR value
2. Check `./scripts/pcr.sh read` to see current PCR state
3. If PCR 14/15, device may need reboot

### PCR shows unexpected value

```bash
./scripts/pcr.sh read 14
# Shows non-zero value on fresh boot
```

Something extended the PCR before your script. Check:
- Other TPM-using services (clevis, tpm2-abrmd)
- Boot measurement tools
- BIOS/UEFI measured boot

### Cannot reset PCR

```
ERROR: Only PCR 16 (debug PCR) can be reset by software
```

PCRs 0-15 require hardware reboot to reset. This is by design.

## References

- [TCG PC Client Platform TPM Profile](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)
- [tpm2-tools documentation](https://tpm2-tools.readthedocs.io/)
- [INIT.md](INIT.md) - General initialization documentation
