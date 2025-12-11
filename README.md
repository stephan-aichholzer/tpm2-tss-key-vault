# TPM2 RSA Key Management with OpenSSL Integration

This document explains how to create, persist, and use an RSA key stored inside a TPM2 chip, with OpenSSL integration for sign and decrypt operations.

## Related Documentation

| Document | Description |
|----------|-------------|
| [CONCEPT_DOCUMENTATION.md](CONCEPT_DOCUMENTATION.md) | Full security architecture and threat model |
| [key_vault_flow.html](key_vault_flow.html) | Interactive Mermaid diagrams for C++ implementation |
| [tpm_sequence_diagrams.html](tpm_sequence_diagrams.html) | Basic TPM operation sequence diagrams |
| [init.sh](init.sh) | Automated TPM provisioning script |

## Quick Start

For automated setup, use the provisioning script:

```bash
# Run once during initial setup
./init.sh

# Check if already provisioned
./init.sh --check

# Force recreate (removes existing key!)
./init.sh --force
```

Then build and run the C++ examples:

```bash
cd build && cmake .. && make
./tpm_example              # Basic sign/decrypt demo
./key_vault_example        # Full KeyVault with process hardening
```

---

## Overview

The TPM (Trusted Platform Module) is a hardware security chip that can:
- Generate cryptographic keys internally
- Perform crypto operations (sign, decrypt) without exposing private keys
- Bind secrets to specific hardware (keys cannot be migrated)

**Key Security Property:** The private key NEVER leaves the TPM silicon. All cryptographic operations happen inside the chip.

---

## TPM Key Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                     TPM2 Chip                               │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              TPM Internal Seed                       │   │
│  │         (burned into silicon, never exposed)         │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           Primary Key (Storage Root)                 │   │
│  │         derived deterministically from seed          │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Child RSA Key                           │   │
│  │     - can sign                                       │   │
│  │     - can decrypt                                    │   │
│  │     - fixedtpm (cannot leave this TPM)              │   │
│  │     - persisted at handle 0x81010002                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Step-by-Step Guide

### Prerequisites

```bash
# Required packages (Ubuntu/Debian)
sudo apt install tpm2-tools tpm2-openssl

# Verify TPM access
tpm2_getrandom 8 --hex

# Verify OpenSSL TPM2 provider
openssl list -providers -provider tpm2
```

### Step 1: Create Primary Key (Storage Root)

```bash
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| `-C` | `o` | Owner hierarchy (TPM's main trust root) |
| `-g` | `sha256` | Hash algorithm for key name |
| `-G` | `rsa` | Key algorithm |
| `-c` | `primary.ctx` | Output context file |

**What happens:**
- TPM derives a primary key from its internal seed
- This key is deterministic (same seed = same key)
- Used as parent to wrap/protect child keys
- Context file is a temporary handle, not the actual key

### Step 2: Create RSA Child Key

```bash
tpm2_create -C primary.ctx -G rsa2048 \
    -u rsakey.pub -r rsakey.priv \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign"
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| `-C` | `primary.ctx` | Parent key context |
| `-G` | `rsa2048` | 2048-bit RSA key |
| `-u` | `rsakey.pub` | Public portion output |
| `-r` | `rsakey.priv` | Private portion output (encrypted!) |
| `-a` | attributes | Key properties (see below) |

**Key Attributes Explained:**

| Attribute | Meaning |
|-----------|---------|
| `fixedtpm` | Key can ONLY be used on this specific TPM |
| `fixedparent` | Cannot be moved to different parent key |
| `sensitivedataorigin` | Private key generated inside TPM (not imported) |
| `userwithauth` | Authorized with user auth (password, empty by default) |
| `decrypt` | Key can perform decryption |
| `sign` | Key can perform signing |

**Critical Security Note:**

The file `rsakey.priv` does NOT contain the actual private key!

```
rsakey.priv = Encrypt(actual_private_key, primary_key)
```

It's an encrypted blob that only THIS TPM can decrypt using its primary key. The file is useless on any other system.

### Step 3: Load Key into TPM

```bash
tpm2_load -C primary.ctx -u rsakey.pub -r rsakey.priv -c rsakey.ctx
```

| Parameter | Description |
|-----------|-------------|
| `-C primary.ctx` | Parent key to decrypt the private blob |
| `-u rsakey.pub` | Public portion |
| `-r rsakey.priv` | Encrypted private portion |
| `-c rsakey.ctx` | Output: loaded key context |

**What happens:**
- TPM loads the encrypted private blob
- Decrypts it internally using the primary key
- Key is now usable but temporary (lost on reboot)

### Step 4: Persist Key in TPM NV Storage

```bash
tpm2_evictcontrol -C o -c rsakey.ctx 0x81010002
```

| Parameter | Description |
|-----------|-------------|
| `-C o` | Owner hierarchy authorization |
| `-c rsakey.ctx` | Key to persist |
| `0x81010002` | Persistent handle address |

**What happens:**
- Key is saved in TPM's non-volatile memory
- Survives reboots
- Accessible via handle `0x81010002`
- No need to reload from files

**Persistent Handle Ranges:**

| Range | Owner |
|-------|-------|
| `0x81000000 - 0x8100FFFF` | Owner hierarchy |
| `0x81010000 - 0x8101FFFF` | Endorsement hierarchy |
| `0x81020000 - 0x8102FFFF` | Platform hierarchy |

### Step 5: Export Public Key

```bash
tpm2_readpublic -c 0x81010002 -f pem -o tpm_rsa_pub.pem
```

Exports the public key in standard PEM format. This can be:
- Shared with external parties
- Used to encrypt data for the TPM
- Used to verify signatures from the TPM

---

## Using the Key with OpenSSL

### Sign Data

```bash
# Create test data
echo "Hello TPM" > message.txt

# Sign using TPM (private key never leaves chip)
openssl pkeyutl -provider tpm2 -provider default \
    -sign -inkey handle:0x81010002 \
    -rawin -in message.txt -out message.sig

# Verify using public key (standard OpenSSL)
openssl pkeyutl -verify \
    -pubin -inkey tpm_rsa_pub.pem \
    -rawin -in message.txt -sigfile message.sig
```

### Decrypt Data

```bash
# Encrypt with public key (can be done anywhere)
openssl pkeyutl -encrypt \
    -pubin -inkey tpm_rsa_pub.pem \
    -in secret.txt -out secret.enc

# Decrypt with TPM (only works on this hardware)
openssl pkeyutl -provider tpm2 -provider default \
    -decrypt -inkey handle:0x81010002 \
    -in secret.enc -out secret.dec
```

---

## File Summary

| File | Contents | Security | Can Delete? |
|------|----------|----------|-------------|
| `primary.ctx` | Temporary handle to primary key | Not sensitive | Yes, after step 4 |
| `rsakey.pub` | TPM2 format public key | Public | Yes, after step 4 |
| `rsakey.priv` | Encrypted private key blob | Useless without this TPM | Yes, after step 4 |
| `rsakey.ctx` | Temporary loaded key handle | Not sensitive | Yes, after step 4 |
| `tpm_rsa_pub.pem` | PEM format public key | Public | Keep for verification |

After persisting (step 4), you only need the handle `0x81010002` to use the key.

---

## Security Properties

### What an attacker CANNOT do:

1. **Clone the disk** → Key won't work on different hardware
2. **Extract private key from rsakey.priv** → It's encrypted by TPM
3. **Read private key from memory** → It never leaves TPM silicon
4. **Use the key remotely** → Must have physical access to TPM

### What an attacker with root access CAN do:

1. **Use the key for operations** → If they can talk to TPM
2. **Delete the key** → Destructive, but not theft

### Mitigation for root access threat:

- Bind key to PCR values (unseals only if system state matches)
- Add authorization policy (password, signed policy)
- Use TPM locality restrictions

---

## Cleanup Commands

```bash
# Remove persisted key
tpm2_evictcontrol -C o -c 0x81010002

# Clear all TPM state (DANGEROUS - erases everything)
# tpm2_clear

# List persistent handles
tpm2_getcap handles-persistent
```

---

## Integration Notes

### For C++ with OpenSSL 3.x

See the complete examples in the source files:

| File | Description |
|------|-------------|
| `tpm_example.cpp` | Basic TPM sign/decrypt operations |
| `key_vault.h` | KeyVault API with SecureBuffer and ProtectedPassphrase |
| `key_vault.cpp` | Full implementation with PIMPL idiom |
| `key_vault_example.cpp` | Complete demo with process hardening |
| `process_hardening.h/.cpp` | Memory protection utilities |

#### Basic TPM Key Loading

```cpp
#include <openssl/provider.h>
#include <openssl/store.h>

// Load TPM2 and default providers
OSSL_PROVIDER_load(NULL, "tpm2");
OSSL_PROVIDER_load(NULL, "default");

// Load key from persistent TPM handle
OSSL_STORE_CTX *store = OSSL_STORE_open(
    "handle:0x81010002", NULL, NULL, NULL, NULL);

// Iterate to find the key
while (!OSSL_STORE_eof(store)) {
    OSSL_STORE_INFO *info = OSSL_STORE_load(store);
    if (info && OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
        EVP_PKEY *pkey = OSSL_STORE_INFO_get1_PKEY(info);
        // Use pkey for sign/decrypt operations
        // Private key operations happen INSIDE the TPM
    }
    OSSL_STORE_INFO_free(info);
}
OSSL_STORE_close(store);
```

#### Important: Separate Context for Encryption

The TPM2 provider does not support encryption (only decryption). When encrypting
with the public key, use a separate library context:

```cpp
// Create context with ONLY the default provider
OSSL_LIB_CTX *enc_ctx = OSSL_LIB_CTX_new();
OSSL_PROVIDER_load(enc_ctx, "default");

// Load public key in this context
EVP_PKEY *pubkey = load_public_key_in_context(enc_ctx, "keys/tpm_rsa_pub.pem");

// Encrypt using default provider (not TPM)
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(enc_ctx, pubkey, NULL);
EVP_PKEY_encrypt_init(ctx);
EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, inlen);
```

### For Poco Crypto

Poco's `Crypto::RSAKey` typically loads from PEM files. For TPM integration:
1. Use OpenSSL directly for TPM operations (as shown above)
2. Wrap in a custom class that mimics Poco interface
3. Use `EVP_PKEY` directly with OpenSSL APIs
4. Consider the KeyVault class as a reference implementation

---

## Hybrid Architecture for User Keys

For systems where users provide their own encrypted PEM keys, see
[CONCEPT_DOCUMENTATION.md](CONCEPT_DOCUMENTATION.md) for the complete
security architecture:

```
┌───────────────────────────────────────────────────────────────┐
│                        TPM2 Chip                              │
│   ┌───────────────────────────────────────────────────────┐   │
│   │         Root RSA Key (0x81010002)                     │   │
│   │         - Created by init.sh                          │   │
│   │         - Encrypts user passphrases                   │   │
│   │         - NEVER leaves silicon                        │   │
│   └───────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
                             │
                             │ protects
                             ▼
┌───────────────────────────────────────────────────────────────┐
│                    Database/Storage                           │
│                                                               │
│   key_id: "user_A"                                            │
│   encrypted_passphrase: [256 bytes - RSA encrypted]           │
│   pem_path: "/keys/user_A.pem"                                │
│                                                               │
│   (Encrypted passphrase useless without THIS TPM)             │
└───────────────────────────────────────────────────────────────┘
```

The KeyVault C++ class implements this pattern with:
- `SecureBuffer`: mlock'd memory with secure wipe
- `ProtectedPassphrase`: Serializable TPM-encrypted container
- `sign_with_protected_key()`: Complete operation with auto cleanup
- Process hardening: PR_SET_DUMPABLE, mlockall, PR_SET_PTRACER

---

## References

- [tpm2-tools documentation](https://tpm2-tools.readthedocs.io/)
- [tpm2-openssl provider](https://github.com/tpm2-software/tpm2-openssl)
- [TCG TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [OpenSSL 3.x Provider Architecture](https://www.openssl.org/docs/man3.0/man7/provider.html)

