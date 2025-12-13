# KeyVault Demo - Quick Reference

## Basic Usage (No PCR Policy)

```bash
# Provision TPM key
./scripts/init.sh

# Run demo
./source/build/key_vault_example
```

## With PCR Policy (Platform Binding)

### Production Provisioning

```bash
# Clear any existing key
./scripts/clear.sh

# Provision with PCR policy (use device serial, MAC, etc.)
./scripts/init.sh --pcr 16 --pcr-value "DEVICE-SERIAL-001"
```

### Boot-Time Setup

```bash
# Must run BEFORE KeyVault application starts
./scripts/pcr.sh boot
```

### Run Application

```bash
./source/build/key_vault_example
```

## Demo: Simulate Attack (Wrong Device)

```bash
# 1. Reset PCR and extend with wrong value
./scripts/pcr.sh reset 16
./scripts/pcr.sh extend 16 "ATTACKER-DEVICE"

# 2. Try to use KeyVault - FAILS
./source/build/key_vault_example
# Error: tpm:session(1):a policy check failed

# 3. Restore correct value
./scripts/pcr.sh boot

# 4. Works again
./source/build/key_vault_example
```

## Utility Commands

```bash
# List TPM handles
./scripts/list.sh

# Read PCR values
./scripts/pcr.sh read
./scripts/pcr.sh read 16

# Manually extend PCR
./scripts/pcr.sh extend 16 "some-value"

# Reset PCR 16 (debug PCR only)
./scripts/pcr.sh reset 16

# Remove KeyVault key
./scripts/clear.sh
```

## PCR Notes

| PCR | Reset | Use Case |
|-----|-------|----------|
| 14-15 | Reboot only | Production |
| 16 | Software | Demo/Testing |

## Files

```
keys/
├── tpm_rsa_pub.pem   # TPM public key
├── ek.ctx            # Endorsement Key context
├── pcr_policy        # PCR number (if policy enabled)
└── pcr_value         # Identity value (for boot script)
```

## See Also

- `PCR_POLICY.md` - Detailed PCR policy documentation
- `INIT.md` - Initialization process explanation
- `TPM.md` - TPM architecture overview
