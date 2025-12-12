# TPM2 Key Provisioning (init.sh)

Understanding what `init.sh` does and why. This is the most complex part of TPM2.

## TL;DR

```
init.sh creates a hardware-bound key that ONLY works on THIS device.
The private key never exists in plain form outside the TPM chip.
```

## The Big Picture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   MANUFACTURING          FIRST BOOT              YOUR APP (init.sh)         │
│   (factory)              (OS/BIOS)               (you run this)             │
│                                                                             │
│   ┌─────────┐           ┌─────────┐              ┌─────────────┐            │
│   │ EK seed │           │ SRK     │              │ KeyVault    │            │
│   │ burned  │           │ AK      │              │ 0x81010002  │            │
│   │ into    │           │ created │              │ created     │            │
│   │ chip    │           │         │              │             │            │
│   └─────────┘           └─────────┘              └─────────────┘            │
│                                                                             │
│   You don't do this     OS did this              You do this ONCE           │
│                         already                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Types Explained

### EK (Endorsement Key)

```
WHO CREATES IT:  Chip manufacturer (Infineon, STMicro, etc.)
WHEN:            During chip manufacturing
WHERE:           Seed burned into silicon, key derived from seed
PURPOSE:         "I am THIS specific TPM" - identity + session encryption
YOUR ROLE:       Just load it (tpm2_createek) - you can't change it
```

### SRK (Storage Root Key)

```
WHO CREATES IT:  Operating system or BIOS
WHEN:            First boot, OS installation, or TPM ownership
WHERE:           Derived from owner hierarchy seed in TPM
PURPOSE:         Parent key that wraps/protects your application keys
YOUR ROLE:       Use it as parent when creating your keys
```

### Your Application Key (KeyVault)

```
WHO CREATES IT:  You (via init.sh)
WHEN:            When you run init.sh
WHERE:           Generated INSIDE TPM, persisted at 0x81010002
PURPOSE:         Encrypt/decrypt your application's secrets
YOUR ROLE:       Create it, use it, protect it
```

## What init.sh Actually Does

### Step 1-2: Prerequisites

```bash
# Check TPM is accessible
tpm2_getrandom 4 --hex

# Check tpm2-tools installed
command -v tpm2_createprimary
```

Just making sure everything works before we start.

### Step 3: Load EK Context

```bash
tpm2_createek -c keys/ek.ctx -G rsa -u keys/ek.pub
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TPM2 CHIP                                         │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │               ENDORSEMENT SEED (burned at factory)                  │   │
│   └───────────────────────────────┬─────────────────────────────────────┘   │
│                                   │                                         │
│                                   │ tpm2_createek                           │
│                                   │ (derives, doesn't "create")             │
│                                   ▼                                         │
│                        ┌─────────────────────┐                              │
│                        │         EK          │                              │
│                        │  (always the same)  │──────► keys/ek.ctx           │
│                        └─────────────────────┘        (context file)        │
│                                                                             │
│   This EK is used later for ENCRYPTED SESSIONS (bus protection)             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Note**: "createek" is misleading - it DERIVES the EK from a permanent seed. Same seed = same EK, always.

### Step 4: Create Primary Key (SRK)

```bash
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TPM2 CHIP                                         │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                 OWNER HIERARCHY SEED (in TPM)                       │   │
│   └───────────────────────────────┬─────────────────────────────────────┘   │
│                                   │                                         │
│                                   │ tpm2_createprimary -C o                 │
│                                   │ (-C o = owner hierarchy)                │
│                                   ▼                                         │
│                        ┌─────────────────────┐                              │
│                        │    PRIMARY KEY      │                              │
│                        │   (this is SRK)     │──────► primary.ctx           │
│                        │                     │        (temp file)           │
│                        │  "restricted"       │                              │
│                        │  can only wrap keys │                              │
│                        └─────────────────────┘                              │
│                                                                             │
│   The SRK will be the PARENT of our application key.                        │
│   It can only wrap other keys - cannot encrypt your data directly.          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 5: Create Your RSA Key (THE IMPORTANT STEP)

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
│   │       (SRK)         │                                                   │
│   └──────────┬──────────┘                                                   │
│              │                                                              │
│              │  tpm2_create generates keypair INSIDE TPM                    │
│              │                                                              │
│              ▼                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                                                                     │   │
│   │   INSIDE TPM:                                                       │   │
│   │   ┌───────────────┐                                                 │   │
│   │   │ Generate RSA  │                                                 │   │
│   │   │ 2048-bit pair │                                                 │   │
│   │   └───────┬───────┘                                                 │   │
│   │           │                                                         │   │
│   │           ├─────────────────────────────────────────────────────┐   │   │
│   │           │                                                     │   │   │
│   │           ▼                                                     ▼   │   │
│   │   ┌───────────────┐                                  ┌──────────────┐   │
│   │   │  Public Key   │                                  │ Private Key  │   │
│   │   │  (plain)      │                                  │   WRAPPED    │   │
│   │   └───────┬───────┘                                  │   with SRK   │   │
│   │           │                                          └──────┬───────┘   │
│   │           │                                                 │       │   │
│   └───────────┼─────────────────────────────────────────────────┼───────┘   │
│               │                                                 │           │
│               ▼                                                 ▼           │
│         ┌──────────┐                                    ┌───────────┐       │
│         │ key.pub  │                                    │ key.priv  │       │
│         │ (plain)  │                                    │(ENCRYPTED)│       │
│         └──────────┘                                    └───────────┘       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                    │                                             │
                    ▼                                             ▼
              TO FILESYSTEM                                 TO FILESYSTEM
              (can be read)                            (useless without TPM)
```

### What's in key.pub vs key.priv?

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   key.pub (TPM2B_PUBLIC)                 key.priv (TPM2B_PRIVATE)           │
│   ──────────────────────                 ───────────────────────            │
│                                                                             │
│   ┌─────────────────────┐                ┌─────────────────────┐            │
│   │ type: RSA           │                │ iv: [random]        │            │
│   │ bits: 2048          │                │                     │            │
│   │ exponent: 65537     │                │ encrypted_data:     │            │
│   │ modulus: [256 bytes]│                │   Encrypt(          │            │
│   │                     │                │     private_key,    │            │
│   │ attributes:         │                │     SRK             │            │
│   │   fixedtpm          │                │   )                 │            │
│   │   fixedparent       │                │                     │            │
│   │   decrypt           │                │ hmac: [integrity]   │            │
│   │   sign              │                │                     │            │
│   └─────────────────────┘                └─────────────────────┘            │
│                                                                             │
│   READABLE                               ENCRYPTED BLOB                     │
│   Can be shared                          Useless without THIS TPM           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why key.priv is Useless on Other Machines

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   YOUR MACHINE                           ATTACKER'S MACHINE                 │
│                                                                             │
│   TPM Chip A                             TPM Chip B                         │
│   ┌─────────────────┐                    ┌─────────────────┐                │
│   │ Owner Seed: X   │                    │ Owner Seed: Y   │  (different!)  │
│   │      │          │                    │      │          │                │
│   │      ▼          │                    │      ▼          │                │
│   │ SRK: derives    │                    │ SRK: derives    │                │
│   │ from seed X     │                    │ from seed Y     │                │
│   └─────────────────┘                    └─────────────────┘                │
│           │                                      │                          │
│           ▼                                      ▼                          │
│   key.priv encrypted                     key.priv encrypted                 │
│   with SRK-from-X                        with SRK-from-X                    │
│           │                                      │                          │
│           ▼                                      ▼                          │
│       DECRYPTS OK                         CANNOT DECRYPT!                   │
│      (same SRK)                          (wrong SRK)                        │
│                                                                             │
│                        Attacker copies ──────►                              │
│                        key.priv file                                        │
│                                                                             │
│   RESULT: key.priv is HARDWARE BOUND to your TPM                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
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
│   ┌─────────────────┐      ┌─────────────────┐                              │
│   │       SRK       │      │   key.priv      │                              │
│   │  (from step 4)  │─────►│   (encrypted)   │                              │
│   └─────────────────┘      └────────┬────────┘                              │
│                                     │                                       │
│                     SRK decrypts key.priv INSIDE TPM                        │
│                                     │                                       │
│                                     ▼                                       │
│                            ┌─────────────────┐                              │
│                            │  RSA Private    │                              │
│                            │  Key (in RAM)   │                              │
│                            └────────┬────────┘                              │
│                                     │                                       │
│   tpm2_evictcontrol:                │                                       │
│                                     ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         NV STORAGE                                  │   │
│   │  ┌───────────────────────────────────────────────────────────────┐  │   │
│   │  │  0x81010002:                                                  │  │   │
│   │  │    - RSA-2048 key                                             │  │   │
│   │  │    - Attributes: decrypt, sign, fixedtpm                      │  │   │
│   │  │    - Survives reboot                                          │  │   │
│   │  │    - Accessible by handle reference                           │  │   │
│   │  └───────────────────────────────────────────────────────────────┘  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**After this step:** The key is "persistent" - reference it by `0x81010002` without needing SRK, key.pub, or key.priv files.

### Step 7: Export Public Key

```bash
tpm2_readpublic -c 0x81010002 -f pem -o keys/tpm_rsa_pub.pem
```

Exports the public key in OpenSSL-compatible PEM format for encrypting data that only this TPM can decrypt.

## FAQ

### Q: Why do we need SRK if we just use the handle at runtime?

SRK is only needed during provisioning to "wrap" (encrypt) your key's private portion. Once persisted at `0x81010002`, the key is self-contained - SRK's job is done.

### Q: Can I delete key.pub and key.priv after init.sh?

Yes! Once persisted at `0x81010002`, those files aren't needed. init.sh already cleans them up.

### Q: What if I run init.sh again?

It detects the existing key and skips provisioning. Use `--force` to recreate, or `--clear` to remove.

### Q: Why is EK separate from SRK?

Different purposes:
- **EK**: Identity ("I am this TPM") + session encryption
- **SRK**: Key storage ("protect my keys")

Think of EK as your passport, SRK as your safe.

### Q: Is the private key EVER in plain form?

Only **inside the TPM chip** during operations. It's:
- Generated inside TPM (never outside)
- Stored encrypted (wrapped by SRK)
- Decrypted only inside TPM when used
- Never exposed on any bus or in RAM

### Q: What happens if I clone the disk?

The clone is useless without the original TPM:
- `key.priv` is encrypted with SRK
- SRK is derived from TPM's internal seed
- Different TPM = different seed = different SRK = can't decrypt

## Command Reference

```bash
./init.sh              # Create key (first time)
./init.sh --list       # Show TPM contents
./init.sh --check      # Check if key exists
./init.sh --force      # Recreate key
./init.sh --clear      # Remove key and files
./init.sh --handle 0x81010003  # Use different handle
```

## See Also

- [TPM.md](TPM.md) - TPM2 technical details, sessions, TSS2 stack
- [ARCHITECTURE.md](ARCHITECTURE.md) - Security architecture and threat model
