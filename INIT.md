# TPM2 Key Provisioning (init.sh)

Quick overview of what `init.sh` does. For detailed TPM2 concepts, see [TPM.md](TPM.md).

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
│   │ burned  │           │ created │              │ 0x81010002  │            │
│   │ into    │           │         │              │ created     │            │
│   │ chip    │           │         │              │             │            │
│   └─────────┘           └─────────┘              └─────────────┘            │
│                                                                             │
│   You don't do this     OS did this              You do this ONCE           │
│                         already                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Command Reference

```bash
./init.sh                                    # Create key (first time)
./init.sh --pcr 16 --pcr-value "SERIAL"     # Create with PCR policy
./list.sh                                    # Show TPM handles
./clear.sh                                   # Remove key and files
```

## FAQ

### Q: Why is the key hardware-bound?

The private key is encrypted by the SRK (Storage Root Key), which is derived from the TPM's internal seed. Different TPM = different seed = different SRK = cannot decrypt.

### Q: Can I delete key.pub and key.priv after init.sh?

Yes! Once persisted at `0x81010002`, those files aren't needed. init.sh already cleans them up.

### Q: Is the private key EVER in plain form?

Only **inside the TPM chip** during operations. It's:
- Generated inside TPM (never outside)
- Stored encrypted (wrapped by SRK)
- Decrypted only inside TPM when used
- Never exposed on any bus or in RAM

### Q: What happens if I clone the disk?

The clone is useless without the original TPM. See [ARCHITECTURE.md](ARCHITECTURE.md) for threat model.

### Q: How does PCR policy help?

PCR policy binds the key to platform identity. Even if the TPM module is moved to another device, the key won't work. See [PCR_POLICY.md](PCR_POLICY.md).

## See Also

- [TPM.md](TPM.md) - Key hierarchy, EK vs SRK, provisioning details
- [PCR_POLICY.md](PCR_POLICY.md) - Platform binding with PCR policies
- [ARCHITECTURE.md](ARCHITECTURE.md) - Security architecture and threat model
