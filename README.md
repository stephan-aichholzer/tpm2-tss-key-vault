# TPM2 KeyVault

Hardware-bound key management using TPM2 for IoT platforms. Passphrases for user-provided encrypted keys are protected by the TPM - useless without the original hardware.

## Features

- **Hardware Binding**: Keys encrypted with TPM-bound key, survives disk cloning
- **PCR Policy**: Bind keys to platform identity (device serial, etc.) - protects against TPM module theft
- **Encrypted Sessions**: EK-salted AES-128-CFB encrypted bus communication
- **Process Hardening**: mlock, no core dumps, ptrace restrictions, debugger detection
- **Secure Memory**: Auto-wiping SecureBuffer for sensitive data

## Quick Start

```bash
# Prerequisites (Ubuntu/Debian)
sudo apt install libtss2-dev libssl-dev cmake build-essential tpm2-tools

# Build
mkdir -p source/build && cd source/build && cmake .. && make && cd ../..

# Provision TPM (one-time)
./init.sh

# Run demo
./source/build/key_vault_example
```

See [HOW_TO_RUN.md](HOW_TO_RUN.md) for PCR policy demo and [HOW_TO_BUILD.md](HOW_TO_BUILD.md) for detailed build instructions.

## Documentation

| Document | Description |
|----------|-------------|
| [HOW_TO_RUN.md](HOW_TO_RUN.md) | Quick command reference |
| [HOW_TO_BUILD.md](HOW_TO_BUILD.md) | Build and prerequisites |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Security architecture and threat model |
| [TPM.md](TPM.md) | TPM2 concepts: key hierarchy, sessions, provisioning |
| [PCR_POLICY.md](PCR_POLICY.md) | Platform binding with PCR policies |
| [docs/](docs/) | Interactive diagrams (open in browser) |

## Project Structure

```
tpm2/
├── source/                 # C++ implementation
│   ├── key_vault.h/cpp     # Main KeyVault API
│   ├── tss_session.h/cpp   # TSS2 encrypted sessions (EK-salted)
│   ├── process_hardening.* # Memory/process protection
│   └── *_example.cpp       # Demo applications
├── keys/                   # Generated keys (by init.sh)
├── init.sh                 # TPM provisioning script
├── pcr.sh                  # PCR management tool
├── list.sh                 # List TPM handles
├── clear.sh                # Remove TPM key
├── tpm_lib.sh              # Shared shell functions
└── docs/                   # Mermaid diagrams (HTML)
```

## Usage

```cpp
#include "key_vault.h"

// Initialize with TPM (auto-detects PCR policy if configured)
KeyVault vault(0x81010002, "keys/tpm_rsa_pub.pem", "keys/ek.ctx");

// Protect a passphrase (when user uploads key)
auto protected = vault.protect("user_key_A", "secret_passphrase");
// Store protected.serialize() in database

// Later: use the protected key
auto signature = vault.sign_with_protected_key(
    protected, "keys/user_key_A.pem", data);
```

## Security Summary

| Threat | Mitigation |
|--------|------------|
| Disk cloning | TPM-bound encryption |
| TPM module theft | PCR policy binds key to platform identity |
| Bus sniffing | EK-salted encrypted sessions |
| Memory dumps | PR_SET_DUMPABLE=0 |
| Swap exposure | mlock() |
| Debugging | ptrace restrictions, debugger detection |

See [ARCHITECTURE.md](ARCHITECTURE.md) for full threat model.

## License

MIT - See [LICENSE](LICENSE)
