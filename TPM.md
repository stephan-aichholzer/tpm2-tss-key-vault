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
│  │  Storage Root Key (SRK)                               │  │
│  │  - Created by system/owner                           │  │
│  │  - Parent key for application keys                   │  │
│  │  - Wraps/protects child key blobs                    │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Application RSA Key (0x81010002)                     │  │
│  │  - Created during provisioning (init.sh)             │  │
│  │  - Persistent in TPM NV storage                      │  │
│  │  - Used to encrypt/decrypt user passphrases          │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## EK vs SRK: Two Different Purposes

The TPM has two fundamental keys that serve completely different purposes:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TPM2 Chip                                   │
│                                                                     │
│   ENDORSEMENT KEY (EK)              STORAGE ROOT KEY (SRK)          │
│   ─────────────────────             ──────────────────────          │
│                                                                     │
│   "Who am I?"                       "Protect my stuff"              │
│                                                                     │
│   ┌─────────────┐                   ┌─────────────┐                 │
│   │     EK      │                   │     SRK     │                 │
│   │  (identity) │                   │  (storage)  │                 │
│   └──────┬──────┘                   └──────┬──────┘                 │
│          │                                 │                        │
│          ▼                                 ▼                        │
│   • Session salting                 • Wrap app keys                 │
│   • Remote attestation              • Key hierarchy root            │
│   • TPM identity proof              • Encrypt key blobs             │
│                                                                     │
│          │                                 │                        │
│          ▼                                 ▼                        │
│   ┌─────────────┐                   ┌─────────────┐                 │
│   │  Encrypted  │                   │  Your App   │                 │
│   │   Session   │                   │    Keys     │                 │
│   └─────────────┘                   └─────────────┘                 │
│                                            │                        │
│                                            ▼                        │
│                                     ┌─────────────┐                 │
│                                     │ 0x81010002  │ ← KeyVault      │
│                                     └─────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Comparison

| | Endorsement Key (EK) | Storage Root Key (SRK) |
|---|------------------------|----------------------|
| **Purpose** | Identity + session key agreement | Wrap/protect other keys |
| **Created by** | Factory-burned seed (chip manufacturer) | TPM owner (you/system) |
| **Can encrypt external data?** | No (`restricted`) | No (`restricted`) |
| **Can sign external data?** | No | No |
| **Primary use** | Prove "I am THIS TPM" | Parent for your app keys |
| **Hierarchy** | Endorsement (0x81010xxx) | Owner (0x81000xxx) |

### What `restricted` Means

Both EK and SRK have the `restricted` attribute, meaning they can **only** operate on TPM-internal data:

- **EK**: Can only decrypt session salts (TPM-generated challenges)
- **SRK**: Can only wrap/unwrap child keys (TPM-internal key blobs)

Your **application key** (0x81010002) does NOT have `restricted`, so it can encrypt/decrypt external data (like passphrases).

### How KeyVault Uses Both

| Key | Role in KeyVault |
|-----|------------------|
| **EK** | Salt encrypted sessions → protects bus communication |
| **SRK** | Parent of RSA key → protects key blob on disk |
| **0x81010002** | Encrypts/decrypts passphrases → your actual work key |

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

TPM2 supports several session types:

| Session Type | Purpose | Used When |
|--------------|---------|-----------|
| `TPM2_SE_HMAC` | Authentication + encryption | Key without policy |
| `TPM2_SE_POLICY` | Policy-based authorization | Key with PCR policy |
| `TPM2_SE_TRIAL` | Policy testing without execution | During key creation |

The KeyVault automatically selects the appropriate session type based on whether a PCR policy is configured. See [PCR_POLICY.md](PCR_POLICY.md) for platform binding details.

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

The `init.sh` script provisions the TPM for use. This is the **key moment** where hardware binding happens.

### Usage

```bash
# Basic provisioning
./scripts/init.sh

# With PCR policy - binds key to platform identity
./scripts/init.sh --pcr 16 --pcr-value "DEVICE-SERIAL-001"

# Check existing keys
./scripts/list.sh

# Remove key for reprovisioning
./scripts/clear.sh
```

For PCR policy details, see [PCR_POLICY.md](PCR_POLICY.md).

### Provisioning Steps Overview

```bash
# Step 1-2: Prerequisites check (TPM accessible, tools installed)
# Step 3:   Create EK context (for encrypted sessions)
# Step 4:   Create primary storage key (SRK)
# Step 5:   (Optional) Setup PCR policy
# Step 6:   Create RSA key wrapped by SRK (with policy if specified)
# Step 7:   Load and persist at 0x81010002
# Step 8:   Export public key as PEM
```

### Step 3: Create Endorsement Key Context

```bash
tpm2_createek -c keys/ek.ctx -G rsa -u keys/ek.pub
```

The EK is factory-burned - this just loads it for use in session salting.

### Step 4: Create Primary Storage Key (SRK)

```bash
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TPM2 CHIP                                         │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                    OWNER HIERARCHY SEED                             │   │
│   │              (burned into chip at manufacturing)                    │   │
│   └───────────────────────────────┬─────────────────────────────────────┘   │
│                                   │                                         │
│                                   │ tpm2_createprimary                      │
│                                   │ derives SRK from seed                   │
│                                   ▼                                         │
│                        ┌─────────────────────┐                              │
│                        │    PRIMARY KEY      │                              │
│                        │  (Storage Root Key) │                              │
│                        │                     │                              │
│                        │  private: inside    │                              │
│                        │  public:  primary.ctx                              │
│                        └─────────────────────┘                              │
│                                                                             │
│   Note: This is DETERMINISTIC - same seed always produces same SRK.        │
│   The SRK is "restricted" - can only wrap other keys, not external data.   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 5: Create RSA Key (Wrapped by SRK)

```bash
tpm2_create -C primary.ctx -G rsa2048 -u key.pub -r key.priv \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign"
```

This is where **hardware binding** happens:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TPM2 CHIP                                         │
│                                                                             │
│   ┌─────────────────────┐                                                   │
│   │    PRIMARY KEY      │                                                   │
│   │  (Storage Root Key) │                                                   │
│   └──────────┬──────────┘                                                   │
│              │                                                              │
│              │ tpm2_create generates RSA keypair INSIDE TPM                 │
│              │ then wraps the private key with SRK                          │
│              ▼                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                                                                      │  │
│   │   RSA Private Key ────────► Encrypt(SRK) ────────► key.priv         │  │
│   │   (generated inside)        (wrapped blob)         (to filesystem)  │  │
│   │                                                                      │  │
│   │   RSA Public Key  ────────────────────────────────► key.pub         │  │
│   │   (plain, can export)                              (to filesystem)  │  │
│   │                                                                      │  │
│   └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │     FILESYSTEM        │
                        │                       │
                        │  key.pub  (plain)     │
                        │  key.priv (WRAPPED!)  │
                        │  └─ encrypted with    │
                        │     SRK from THIS TPM │
                        └───────────────────────┘
```

**Why key.priv is useless on other systems:**

```
┌───────────────────────────────────────────────────────────────────────────┐
│                                                                           │
│  key.priv = Encrypt(rsa_private_key, SRK)                                 │
│                                                                           │
│  SRK is derived from TPM's internal seed (unique per chip)                │
│                                                                           │
│  ATTACKER copies key.priv to another machine:                             │
│                                                                           │
│    Different TPM → Different seed → Different SRK → Cannot decrypt!       │
│                                                                           │
│  Result: key.priv is USELESS without the original TPM                     │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

### Step 6: Load and Persist

```bash
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c key.ctx 0x81010002
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TPM2 CHIP                                         │
│                                                                             │
│   tpm2_load:                                                                │
│   ┌─────────────────────┐      ┌─────────────────┐                          │
│   │    PRIMARY KEY      │      │    key.priv     │                          │
│   │  (Storage Root Key) │─────►│   (wrapped)     │                          │
│   └─────────────────────┘      └────────┬────────┘                          │
│              │                          │                                   │
│              │     SRK decrypts the wrapped blob                            │
│              │                          │                                   │
│              │                          ▼                                   │
│              │                 ┌─────────────────┐                          │
│              │                 │ RSA Private Key │                          │
│              │                 │ (now in memory) │                          │
│              │                 └────────┬────────┘                          │
│              │                          │                                   │
│   ───────────┼──────────────────────────┼───────────────────────────────    │
│              │                          │                                   │
│   tpm2_evictcontrol:                    │                                   │
│              │                          ▼                                   │
│   ┌──────────┴────────────────────────────────────────────────────────┐     │
│   │                         NV STORAGE                                │     │
│   │  ╔════════════════════════════════════════════════════════════╗   │     │
│   │  ║   0x81010002  RSA-2048 (KeyVault Application Key)          ║   │     │
│   │  ║   - Attributes: decrypt, sign, fixedtpm, fixedparent       ║   │     │
│   │  ║   - Survives reboot                                        ║   │     │
│   │  ╚════════════════════════════════════════════════════════════╝   │     │
│   └───────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 7: Export Public Key

```bash
tpm2_readpublic -c 0x81010002 -f pem -o keys/tpm_rsa_pub.pem
```

The public key is exported for applications to encrypt data that only this TPM can decrypt.

### Complete Provisioning Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PROVISIONING SUMMARY                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Step 3: tpm2_createek                                                     │
│           Load EK context → enables encrypted sessions                      │
│                                                                             │
│   Step 4: tpm2_createprimary                                                │
│           Derive SRK from seed → parent for our key                         │
│                                                                             │
│   Step 5: tpm2_create                                                       │
│           Generate RSA key → wrap private with SRK → key.pub + key.priv     │
│           ↑↑↑ THIS IS THE HARDWARE BINDING MOMENT ↑↑↑                       │
│                                                                             │
│   Step 6: tpm2_load + tpm2_evictcontrol                                     │
│           Unwrap with SRK → save to NV at 0x81010002                        │
│                                                                             │
│   Step 7: tpm2_readpublic                                                   │
│           Export public key as PEM                                          │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  Result: Private key exists ONLY in this TPM's NV storage                   │
│          key.priv on disk is wrapped (useless without this TPM)             │
│          Public key can be shared freely                                    │
└─────────────────────────────────────────────────────────────────────────────┘
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
