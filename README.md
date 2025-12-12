# TPM2 KeyVault

Hardware-bound key management using TPM2 for IoT platforms. Passphrases for user-provided encrypted keys are protected by the TPM - useless without the original hardware.

## Features

- **Hardware Binding**: Keys encrypted with TPM-bound key, survives disk cloning
- **Encrypted Sessions**: EK-salted AES-128-CFB encrypted bus communication
- **Process Hardening**: mlock, no core dumps, ptrace restrictions
- **Secure Memory**: Auto-wiping SecureBuffer for sensitive data

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Security architecture and threat model |
| [TPM.md](TPM.md) | TPM2 implementation: EK, sessions, TSS2 stack |

## Quick Start

```bash
# Prerequisites (Ubuntu/Debian)
sudo apt install libtss2-dev libssl-dev cmake build-essential tpm2-tools

# Provision TPM (one-time)
bash init.sh

# Build
cd source/build && cmake .. && make && cd ../..

# Run demo
./source/build/key_vault_example
```

## Project Structure

```
tpm2/
├── source/                 # C++ implementation
│   ├── key_vault.h/cpp     # Main KeyVault API
│   ├── tss_session.h/cpp   # TSS2 encrypted sessions
│   ├── process_hardening.* # Memory/process protection
│   └── *_example.cpp       # Demo applications
├── keys/                   # Generated keys (by init.sh)
├── init.sh                 # TPM provisioning script
├── ARCHITECTURE.md         # Security design
├── TPM.md                  # TPM2/TSS2 details
└── LICENSE                 # MIT
```

## Usage

```cpp
#include "key_vault.h"

// Initialize with TPM
KeyVault vault(0x81010002, "keys/tpm_rsa_pub.pem", "keys/ek.ctx");

// Protect a passphrase (when user uploads key)
auto protected = vault.protect("user_key_A", "secret_passphrase");
// Store protected.serialize() in database

// Later: use the protected key
auto signature = vault.sign_with_protected_key(
    protected, "keys/user_key_A.pem", data);
```

## Security Summary

| Protected Against | Mechanism |
|-------------------|-----------|
| Disk cloning | TPM-bound encryption |
| Bus sniffing | EK-salted encrypted sessions |
| Memory dumps | PR_SET_DUMPABLE=0 |
| Swap exposure | mlock() |
| Debugging | ptrace restrictions |

See [ARCHITECTURE.md](ARCHITECTURE.md) for full threat model.

## License

MIT - See [LICENSE](LICENSE)
