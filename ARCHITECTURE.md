# TPM2 Security Architecture - Concept Documentation

This document describes the security architecture and principles used in the TPM2-protected key management system for IoT platforms.

## Table of Contents

1. [Overview](#overview)
2. [Threat Model](#threat-model)
3. [Security Architecture](#security-architecture)
4. [Key Hierarchy](#key-hierarchy)
5. [Protection Mechanisms](#protection-mechanisms)
6. [Runtime Flow](#runtime-flow)
7. [Security Boundaries](#security-boundaries)
8. [Implementation Components](#implementation-components)

---

## Overview

This system provides secure storage and usage of cryptographic keys for IoT devices where:

- A **root key** is generated inside the TPM during factory provisioning
- **User-provided keys** (encrypted PEM files) can be uploaded at runtime
- Passphrases for user keys are **encrypted by the TPM** and stored safely
- Keys are only decrypted **briefly in memory** when needed for operations
- Multiple layers of **process hardening** minimize the attack surface

### Design Goals

| Goal | Solution |
|------|----------|
| Root key never extractable | Generated and stored inside TPM silicon |
| Survive disk cloning | All secrets encrypted with TPM-bound key |
| Minimize memory exposure | SecureBuffer with mlock + immediate wipe |
| Prevent debugging attacks | PR_SET_DUMPABLE=0, ptrace restrictions |
| Support user-provided keys | Hybrid model with TPM-protected passphrases |

---

## Threat Model

### Threats Addressed

| Threat | Attack Vector | Mitigation |
|--------|---------------|------------|
| **Device Theft** | Attacker steals device, extracts storage | TPM-bound encryption - data useless on other hardware |
| **Disk Cloning** | Attacker copies SD card/SSD | Encrypted passphrases require original TPM |
| **Database Breach** | Attacker dumps application database | Passphrase blobs encrypted, need TPM to decrypt |
| **Cold Boot Attack** | Freeze RAM, extract contents | mlock() prevents swap, brief exposure window |
| **Core Dump Analysis** | Trigger crash, analyze dump | PR_SET_DUMPABLE=0 prevents dumps |
| **Process Debugging** | ptrace attach to read memory | PR_SET_PTRACER restrictions, non-dumpable process |
| **/proc/mem Reading** | Read /proc/<pid>/mem | Requires CAP_SYS_PTRACE when non-dumpable |
| **Swap File Analysis** | Read secrets from swap partition | mlock() keeps sensitive data in RAM only |

### Threats NOT Fully Addressed

| Threat | Why | Mitigation Level |
|--------|-----|------------------|
| **Root with CAP_SYS_PTRACE** | Can bypass ptrace restrictions | Minimal - ~ms window during operations |
| **Kernel Module Attack** | Direct memory access | None - outside scope |
| **Physical TPM Attack** | Decap chip, probe buses | Extremely difficult, requires lab equipment |
| **Side Channel Attacks** | Timing, power analysis | Depends on TPM implementation |

### Security Boundary

```
┌─────────────────────────────────────────────────────────────────┐
│                    FULLY PROTECTED                              │
│  - Data at rest (encrypted passphrases, encrypted PEM files)    │
│  - Root private key (never leaves TPM)                          │
│  - Offline attacks (disk cloning, theft)                        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    HARDENED (High Bar)                          │
│  - Memory during operations (mlock, secure wipe)                │
│  - Process debugging (ptrace restrictions)                      │
│  - Crash analysis (no core dumps)                               │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    VULNERABLE WINDOW                            │
│  - Root attacker with CAP_SYS_PTRACE during key operation       │
│  - Duration: milliseconds                                       │
│  - Requires: active monitoring, precise timing                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Hybrid Key Model

The system uses a hybrid approach to balance security with flexibility:

```
┌─────────────────────────────────────────────────────────────────┐
│                         TPM2 Chip                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   ROOT RSA KEY                           │   │
│  │              (Generated inside TPM)                      │   │
│  │           (NEVER leaves silicon)                         │   │
│  │                                                          │   │
│  │  Used for:                                               │   │
│  │  • Encrypting user key passphrases                       │   │
│  │  • Platform identity/attestation                         │   │
│  │  • Root of trust for security tree                       │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                    encrypts/decrypts
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Storage (DB/Filesystem)                      │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              PROTECTED PASSPHRASES                        │  │
│  │                                                           │  │
│  │  key_id: "user_key_A"                                     │  │
│  │  encrypted_data: [RSA-encrypted passphrase blob]          │  │
│  │                                                           │  │
│  │  → Useless without THIS specific TPM                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              ENCRYPTED PEM FILES                          │  │
│  │                                                           │  │
│  │  user_key_A.pem (AES-256-CBC encrypted)                   │  │
│  │  user_key_B.pem (AES-256-CBC encrypted)                   │  │
│  │                                                           │  │
│  │  → Protected by passphrase (which is TPM-protected)       │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Why Hybrid?

| Approach | Pros | Cons |
|----------|------|------|
| **All keys in TPM** | Maximum security, keys never extractable | Users can't bring their own keys |
| **All keys in files** | Maximum flexibility | Vulnerable to disk cloning |
| **Hybrid (our approach)** | Good security + user key support | Brief memory exposure window |

---

## Key Hierarchy

### TPM Key Structure

```
TPM Internal Seed (burned in manufacturing)
         │
         │ Derived deterministically
         ▼
┌─────────────────────────────────────────┐
│         PRIMARY KEY (Storage Root)       │
│         Handle: transient                │
│         Type: RSA-2048                   │
│         Purpose: Wrap child keys         │
└─────────────────────────────────────────┘
         │
         │ Parent of
         ▼
┌─────────────────────────────────────────┐
│         ROOT RSA KEY                     │
│         Handle: 0x81010002 (persistent)  │
│         Type: RSA-2048                   │
│         Attributes:                      │
│           - fixedtpm (bound to this TPM) │
│           - fixedparent                  │
│           - sensitivedataorigin          │
│           - sign | decrypt               │
│         Purpose:                         │
│           - Encrypt/decrypt passphrases  │
│           - Sign platform data           │
└─────────────────────────────────────────┘
```

### Key Attributes Explained

| Attribute | Meaning | Security Impact |
|-----------|---------|-----------------|
| `fixedtpm` | Key cannot be duplicated to another TPM | Prevents key extraction |
| `fixedparent` | Key cannot be moved to different parent | Maintains hierarchy |
| `sensitivedataorigin` | Key generated inside TPM | Never existed outside |
| `sign` | Key can create signatures | For authentication |
| `decrypt` | Key can decrypt data | For passphrase unwrapping |

---

## Protection Mechanisms

### Layer 1: TPM Hardware Binding

**What it protects against:** Disk cloning, device theft, offline attacks

```cpp
// Passphrase encrypted with TPM public key
std::vector<uint8_t> encrypted = encrypt_with_tpm_pubkey(passphrase);
// Store encrypted blob in database
db.store(key_id, encrypted);

// Later: Only THIS TPM can decrypt
SecureBuffer passphrase = tpm_decrypt(encrypted);  // TPM operation
```

**Key property:** The encrypted blob is cryptographically useless without access to the specific TPM that holds the private key.

### Layer 2: Secure Memory (SecureBuffer)

**What it protects against:** Swap exposure, memory disclosure after free

```cpp
class SecureBuffer {
    SecureBuffer(size_t size) {
        data_ = new uint8_t[size];
        mlock(data_, size);        // Prevent swapping to disk
    }

    ~SecureBuffer() {
        // Secure wipe - volatile prevents optimization
        volatile uint8_t* p = data_;
        for (size_t i = 0; i < size_; ++i) {
            p[i] = 0;
        }
        munlock(data_, size_);
        delete[] data_;
    }
};
```

**Key properties:**
- Memory locked in RAM (never swapped)
- Zeroed on destruction (not just freed)
- Volatile pointer prevents compiler from optimizing away the wipe

### Layer 3: Process Hardening

**What it protects against:** Core dumps, debugging, /proc/mem reading

```cpp
void harden_process() {
    // Prevent core dumps and /proc/pid/mem access
    prctl(PR_SET_DUMPABLE, 0);

    // Restrict ptrace
    prctl(PR_SET_PTRACER, 0);

    // Lock all memory
    mlockall(MCL_CURRENT | MCL_FUTURE);

    // Disable core dumps via resource limit
    struct rlimit core_limit = {0, 0};
    setrlimit(RLIMIT_CORE, &core_limit);
}
```

**Effect of PR_SET_DUMPABLE=0:**

| Operation | Without | With |
|-----------|---------|------|
| Core dump on crash | Generated | Blocked |
| /proc/pid/mem read | Allowed (same user) | Requires CAP_SYS_PTRACE |
| ptrace attach | Allowed (same user) | Requires CAP_SYS_PTRACE |
| gdb attach | Works | Fails |

### Layer 4: Minimal Exposure Window

**What it protects against:** Reduces time window for memory inspection attacks

```cpp
std::vector<uint8_t> sign_with_protected_key(...) {
    // === WINDOW OPENS ===

    // 1. TPM decrypts passphrase (inside silicon)
    SecureBuffer passphrase = tpm_decrypt(encrypted_blob);

    // 2. Load PEM using passphrase
    EVP_PKEY* pkey = load_encrypted_pem(pem_path, passphrase);

    // 3. Passphrase wiped immediately
    passphrase.wipe();  // Explicit wipe (also in destructor)

    // 4. Perform operation
    auto signature = sign(pkey, data);

    // 5. Key freed
    EVP_PKEY_free(pkey);

    // === WINDOW CLOSES ===

    return signature;  // Only signature leaves scope
}
```

**Timeline:**
```
Time ─────────────────────────────────────────────────────────▶
     │                         │                    │
     │                         │                    │
  Passphrase                Private Key         Operation
  decrypted                 loaded              complete
  (in SecureBuffer)        (in OpenSSL)        (all wiped)
     │                         │                    │
     ├─────────────────────────┼────────────────────┤
     │    VULNERABLE WINDOW: ~1-10 milliseconds    │
```

---

## Runtime Flow

### Provisioning Flow (Factory)

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Factory   │     │    TPM      │     │   Storage   │
│   Admin     │     │    Chip     │     │             │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │  init.sh          │                   │
       │──────────────────▶│                   │
       │                   │                   │
       │  Create primary   │                   │
       │──────────────────▶│                   │
       │                   │ Generate key      │
       │                   │ from seed         │
       │◀──────────────────│                   │
       │                   │                   │
       │  Create RSA key   │                   │
       │──────────────────▶│                   │
       │                   │ Generate inside   │
       │                   │ TPM               │
       │◀──────────────────│                   │
       │                   │                   │
       │  Persist at       │                   │
       │  0x81010002       │                   │
       │──────────────────▶│                   │
       │                   │ Store in NV       │
       │◀──────────────────│                   │
       │                   │                   │
       │  Export public    │                   │
       │──────────────────▶│                   │
       │◀──────────────────│                   │
       │                   │                   │
       │  Save public key  │                   │
       │─────────────────────────────────────▶│
       │                   │                   │
       ▼                   ▼                   ▼
```

### User Key Upload Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    User     │     │    App      │     │    TPM      │     │     DB      │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │ Upload PEM +      │                   │                   │
       │ passphrase        │                   │                   │
       │──────────────────▶│                   │                   │
       │                   │                   │                   │
       │                   │ Load TPM pubkey   │                   │
       │                   │──────────────────▶│                   │
       │                   │◀──────────────────│                   │
       │                   │                   │                   │
       │                   │ RSA encrypt       │                   │
       │                   │ passphrase        │                   │
       │                   │ (with pubkey)     │                   │
       │                   │                   │                   │
       │                   │ Store encrypted   │                   │
       │                   │ blob              │                   │
       │                   │─────────────────────────────────────▶│
       │                   │                   │                   │
       │                   │ Store encrypted   │                   │
       │                   │ PEM file          │                   │
       │                   │─────────────────────────────────────▶│
       │                   │                   │                   │
       │ Success           │                   │                   │
       │◀──────────────────│                   │                   │
       │                   │                   │                   │
       │ (passphrase       │                   │                   │
       │  wiped from       │                   │                   │
       │  memory)          │                   │                   │
       ▼                   ▼                   ▼                   ▼
```

### Key Usage Flow (Runtime)

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Service   │     │  KeyVault   │     │    TPM      │     │   OpenSSL   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │ sign_with_        │                   │                   │
       │ protected_key()   │                   │                   │
       │──────────────────▶│                   │                   │
       │                   │                   │                   │
       │                   │ Decrypt           │                   │
       │                   │ passphrase        │                   │
       │                   │──────────────────▶│                   │
       │                   │                   │ RSA decrypt       │
       │                   │                   │ (inside TPM)      │
       │                   │◀──────────────────│                   │
       │                   │                   │                   │
       │                   │ [SecureBuffer: passphrase]            │
       │                   │                   │                   │
       │                   │ Load encrypted PEM│                   │
       │                   │────────────────────────────────────▶ │
       │                   │                   │                   │
       │                   │                   │  Decrypt PEM      │
       │                   │                   │  with passphrase  │
       │                   │◀────────────────────────────────────│
       │                   │                   │                   │
       │                   │ WIPE passphrase   │                   │
       │                   │ (SecureBuffer)    │                   │
       │                   │                   │                   │
       │                   │ Sign data         │                   │
       │                   │─────────────────────────────────────▶│
       │                   │◀────────────────────────────────────│
       │                   │                   │                   │
       │                   │ FREE EVP_PKEY     │                   │
       │                   │ (key wiped)       │                   │
       │                   │                   │                   │
       │ Return signature  │                   │                   │
       │◀──────────────────│                   │                   │
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
```

---

## Security Boundaries

### What Leaves the TPM

| Data | Leaves TPM? | Form |
|------|-------------|------|
| Root private key | **NEVER** | N/A |
| Root public key | Yes | PEM file (safe to share) |
| Encrypted passphrase | Yes (after decryption) | Plaintext in SecureBuffer |
| Signatures | Yes | Created inside TPM |

### What's Stored Where

| Data | Location | Protection |
|------|----------|------------|
| Root private key | TPM NV storage | Hardware-bound, non-extractable |
| Root public key | Filesystem | None needed (public) |
| Protected passphrases | Database | RSA-encrypted with TPM key |
| Encrypted PEM files | Filesystem | AES-256-CBC + passphrase |
| Decrypted passphrase | RAM (brief) | SecureBuffer + mlock |
| Loaded private key | RAM (brief) | EVP_PKEY + immediate free |

---

## Implementation Components

### Class Overview

#### SecureBuffer
Memory buffer with automatic secure wiping:
- Constructor: Allocates and mlocks memory
- Destructor: Securely wipes and munlocks
- Move-only (no copies to prevent multiple wipes)

#### ProtectedPassphrase
Serializable container for TPM-encrypted passphrases:
- `key_id`: Identifier for the key
- `encrypted_data`: RSA-encrypted passphrase blob
- `serialize()`/`deserialize()`: For database storage

#### KeyVault
Main interface for protected key operations:
- `protect()`: Encrypt passphrase with TPM public key
- `load_protected_key()`: Decrypt passphrase, load PEM
- `sign_with_protected_key()`: Complete sign operation
- `decrypt_with_protected_key()`: Complete decrypt operation

#### Process Hardening Functions
- `harden_process()`: Apply all protections
- `check_hardening_status()`: Verify current state
- `print_hardening_status()`: Display status

---

## References

- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [tpm2-tools Documentation](https://tpm2-tools.readthedocs.io/)
- [tpm2-openssl Provider](https://github.com/tpm2-software/tpm2-openssl)
- [OpenSSL 3.0 Provider Architecture](https://www.openssl.org/docs/man3.0/man7/provider.html)
- [Linux prctl Manual](https://man7.org/linux/man-pages/man2/prctl.2.html)
- [mlock Manual](https://man7.org/linux/man-pages/man2/mlock.2.html)
