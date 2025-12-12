# TPM2 Implementation Details

TPM2 integration, session handling, and TSS2 library usage.

For security architecture and threat model, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Overview

The system uses TPM2 (Trusted Platform Module) as the root of trust for protecting cryptographic key passphrases. All sensitive operations use **encrypted sessions** with **Endorsement Key (EK) salting** to protect bus communication.

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                        TPM2 Chip                            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Endorsement Key (EK)                                 │  │
│  │  - Factory-burned by chip manufacturer               │  │
│  │  - Used for session key agreement (salting)          │  │
│  │  - Never used for encryption directly                │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Application RSA Key (0x81010002)                     │  │
│  │  - Created during provisioning (init.sh)             │  │
│  │  - Persistent in TPM NV storage                      │  │
│  │  - Used to encrypt/decrypt user passphrases          │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Endorsement Key (EK)

### What is the EK?

The Endorsement Key is a special RSA key pair that:

1. **Factory-burned**: The private key seed is injected during chip manufacturing (by STMicro, Infineon, NXP, etc.)
2. **Deterministic**: The same EK is always derived from the seed - it's not randomly generated each time
3. **Non-exportable**: The private key never leaves the TPM silicon
4. **Identity**: Can be certified by the manufacturer (EK certificate chain)

### EK vs Application Key

| Property | Endorsement Key (EK) | Application Key |
|----------|---------------------|-----------------|
| Origin | Factory-burned seed | Created by `init.sh` |
| Purpose | Session salting, identity | Encrypt passphrases |
| Attributes | RESTRICTED, DECRYPT | DECRYPT, SIGN |
| Handle | Created on-demand | 0x81010002 (persistent) |

### Why Use EK for Sessions?

Without EK salting:
```
Session Key = KDF(nonce_tss || nonce_tpm)
              ↑               ↑
        Both travel in plaintext on bus!
        Attacker can derive session key.
```

With EK salting:
```
Session Key = KDF(salt || nonce_tss || nonce_tpm)
              ↑
        Salt encrypted with EK public key.
        Only TPM can decrypt → attacker cannot derive key.
```

## Encrypted Sessions

### Session Types

TPM2 supports several session types. We use **HMAC sessions** with encryption:

| Session Type | Purpose |
|--------------|---------|
| `TPM2_SE_HMAC` | Command/response authentication + encryption |
| `TPM2_SE_POLICY` | Policy-based authorization |
| `TPM2_SE_TRIAL` | Policy testing without execution |

### Session Attributes

```c
TPMA_SESSION attrs = TPMA_SESSION_DECRYPT      // Encrypt TO TPM
                   | TPMA_SESSION_ENCRYPT      // Encrypt FROM TPM
                   | TPMA_SESSION_CONTINUESESSION;
```

- **DECRYPT**: Parameters sent TO TPM are encrypted
- **ENCRYPT**: Responses FROM TPM are encrypted
- **CONTINUESESSION**: Session persists across commands

### Encryption Algorithm

Sessions use **AES-128-CFB** for symmetric encryption:

```c
TPMT_SYM_DEF symmetric = {
    .algorithm = TPM2_ALG_AES,
    .keyBits = { .aes = 128 },
    .mode = { .aes = TPM2_ALG_CFB }
};
```

## TSS2 Library Stack

The implementation uses the TPM Software Stack (TSS2):

```
┌─────────────────────────────────────────┐
│           Application (KeyVault)         │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│      ESYS (Enhanced System API)          │
│  - High-level, manages sessions          │
│  - Handles HMAC/encryption automatically │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│              TCTI Loader                 │
│  - Finds appropriate TCTI module         │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│           TCTI (device/tabrmd)           │
│  - /dev/tpmrm0 (resource manager)        │
│  - tpm2-abrmd (user-space daemon)        │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│              TPM2 Hardware               │
└─────────────────────────────────────────┘
```

### Required Libraries

```cmake
pkg_check_modules(TSS2 REQUIRED
    tss2-esys      # Enhanced System API
    tss2-rc        # Return code decoder
    tss2-tctildr   # TCTI loader
    tss2-mu        # Marshaling/unmarshaling
)
```

On Ubuntu/Debian:
```bash
sudo apt install libtss2-dev
```

## Session Establishment Flow

```
Application                    TSS2 Library                    TPM
    │                              │                            │
    │  TssSession(handle)          │                            │
    │─────────────────────────────>│                            │
    │                              │                            │
    │                              │  Esys_Initialize()         │
    │                              │───────────────────────────>│
    │                              │                            │
    │                              │  Esys_TR_FromTPMPublic()   │
    │                              │───────────────────────────>│
    │                              │<───────────────────────────│
    │                              │  key_handle                │
    │                              │                            │
    │                              │  Esys_CreatePrimary(EK)    │
    │                              │───────────────────────────>│
    │                              │<───────────────────────────│
    │                              │  ek_handle                 │
    │                              │                            │
    │                              │  Esys_StartAuthSession()   │
    │                              │  (salted with EK)          │
    │                              │───────────────────────────>│
    │                              │  [salt encrypted w/ EK]    │
    │                              │<───────────────────────────│
    │                              │  session                   │
    │                              │                            │
    │                              │  SetAttributes(ENCRYPT)    │
    │                              │───────────────────────────>│
    │                              │                            │
    │<─────────────────────────────│                            │
    │  session ready               │                            │
```

## Decryption Flow (Protected)

```
Application                    TSS2 Library                    TPM
    │                              │                            │
    │  decrypt(ciphertext)         │                            │
    │─────────────────────────────>│                            │
    │                              │                            │
    │                              │  Esys_RSA_Decrypt()        │
    │                              │  session = encrypted       │
    │                              │───────────────────────────>│
    │                              │  [AES-128-CFB encrypted]   │
    │                              │                            │
    │                              │         RSA decrypt        │
    │                              │        (inside TPM)        │
    │                              │                            │
    │                              │<───────────────────────────│
    │                              │  [AES-128-CFB encrypted]   │
    │                              │                            │
    │<─────────────────────────────│                            │
    │  SecureBuffer(plaintext)     │                            │
```

**Bus traffic is encrypted** - even with physical access to the SPI/LPC bus, an attacker cannot read the plaintext passphrase.

## Provisioning (init.sh)

The `init.sh` script provisions the TPM for use:

```bash
# 1. Create Endorsement Key context (for session salting)
tpm2_createek -c keys/ek.ctx -G rsa -u keys/ek.pub

# 2. Create primary storage key
tpm2_createprimary -C o -c keys/primary.ctx

# 3. Create RSA key with sign+decrypt
tpm2_create -C keys/primary.ctx \
    -G rsa2048 \
    -u keys/rsakey.pub \
    -r keys/rsakey.priv \
    -a "fixedtpm|fixedparent|sensitivedataorigin|decrypt|sign"

# 4. Load and persist at 0x81010002
tpm2_load -C keys/primary.ctx \
    -u keys/rsakey.pub \
    -r keys/rsakey.priv \
    -c keys/rsakey.ctx
tpm2_evictcontrol -C o -c keys/rsakey.ctx 0x81010002

# 5. Export public key
tpm2_readpublic -c 0x81010002 -f pem -o keys/tpm_rsa_pub.pem
```

## Troubleshooting

### "Esys_Initialize failed"

Check TPM device access:
```bash
ls -la /dev/tpm*
# Should show /dev/tpm0 and /dev/tpmrm0

# Check permissions
groups  # Should include 'tss'
```

### "Esys_TR_FromTPMPublic failed"

Key not provisioned:
```bash
bash init.sh  # Run provisioning
```

### "Esys_CreatePrimary (EK) failed"

Endorsement hierarchy may be locked:
```bash
# Check EK creation manually
tpm2_createek -c /tmp/ek.ctx -G rsa
```

### Session Errors

Clear stale sessions:
```bash
# Restart the resource manager
sudo systemctl restart tpm2-abrmd
# Or use kernel RM
sudo systemctl stop tpm2-abrmd
```

## References

- [TCG TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [TCG EK Credential Profile](https://trustedcomputinggroup.org/resource/tcg-ek-credential-profile/)
- [TSS2 ESYS API](https://github.com/tpm2-software/tpm2-tss)
- [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)
