# How to Build

Step-by-step instructions for building the TPM2 KeyVault project.

## Prerequisites

### Ubuntu/Debian

```bash
# TPM2 libraries
sudo apt install libtss2-dev tpm2-tools

# OpenSSL
sudo apt install libssl-dev

# Build tools
sudo apt install cmake build-essential
```

### Verify TPM Access

```bash
# Check TPM device exists
ls -la /dev/tpm*

# Should show:
# /dev/tpm0      - direct TPM access
# /dev/tpmrm0    - resource-managed access (preferred)

# Test TPM works
tpm2_getrandom 8 --hex

# Check your user is in tss group
groups | grep tss

# If not, add yourself:
sudo usermod -aG tss $USER
# Then logout/login
```

## Build Steps

### 1. Clone Repository

```bash
git clone https://github.com/stephan-aichholzer/tpm2-tss-key-vault.git
cd tpm2-tss-key-vault
```

### 2. Provision TPM (One-Time)

```bash
# Creates persistent RSA key at handle 0x81010002
bash init.sh

# To check if already provisioned:
bash init.sh --check

# To recreate (removes existing key):
bash init.sh --force
```

This creates:
- `keys/tpm_rsa_pub.pem` - Public key
- `keys/ek.ctx` - Endorsement Key context
- Persistent key at `0x81010002`

### 3. Build

```bash
mkdir -p source/build
cd source/build
cmake ..
make
```

### 4. Run

```bash
# From project root:
cd ../..

# Basic TPM test
./source/build/tpm_example

# Full KeyVault demo with process hardening
./source/build/key_vault_example
```

## Build Output

After successful build:

```
source/build/
├── tpm_example         # Basic TPM sign/decrypt demo
└── key_vault_example   # Full KeyVault with encrypted sessions
```

## Troubleshooting

### CMake can't find TSS2

```bash
# Check if libtss2-dev is installed
dpkg -l | grep libtss2

# Check pkg-config can find it
pkg-config --libs tss2-esys
```

### Permission denied on /dev/tpm0

```bash
# Add user to tss group
sudo usermod -aG tss $USER

# Logout and login again, then verify:
groups | grep tss
```

### init.sh fails

```bash
# Check TPM is working
tpm2_getcap properties-fixed

# Check for existing key
tpm2_getcap handles-persistent

# Force recreate
bash init.sh --force
```

### Runtime errors

```bash
# "Esys_Initialize failed" - TPM not accessible
ls -la /dev/tpmrm0
sudo systemctl status tpm2-abrmd

# "Handle not found" - Key not provisioned
bash init.sh
```

## Clean Build

```bash
rm -rf source/build
mkdir source/build
cd source/build
cmake ..
make
```

## Dependencies Summary

| Library | Package (Debian/Ubuntu) | Purpose |
|---------|------------------------|---------|
| tss2-esys | libtss2-dev | TPM2 Enhanced System API |
| tss2-rc | libtss2-dev | Return code decoder |
| tss2-tctildr | libtss2-dev | TCTI loader |
| tss2-mu | libtss2-dev | Marshaling utilities |
| OpenSSL | libssl-dev | Crypto operations |
| tpm2-tools | tpm2-tools | CLI tools for init.sh |
