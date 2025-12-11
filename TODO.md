# TODO - Next Session

## Priority: TPM Session Security

The current implementation sends decrypted data over the SPI bus in plaintext.
This is a potential attack vector for physical bus sniffing.

### Issue
- TPM RSA decrypt returns plaintext passphrase over SPI/I2C bus
- Attacker with physical access + logic analyzer can intercept
- Affects discrete TPM chips (STMicroelectronics, Infineon, Nuvoton)
- Does NOT affect Intel PTT (firmware TPM inside CPU)

### Solution: TPM2 Encrypted Sessions
TPM 2.0 supports encrypted and HMAC-authenticated sessions:

```cpp
// TODO: Implement encrypted session for TPM communication
// 1. Start encrypted session with tpm2_startauthsession
// 2. Use session for all sensitive operations
// 3. Session encrypts data on the bus with AES
```

### Resources
- TPM 2.0 spec Part 1, Section 19 (Sessions)
- tpm2-tools: `tpm2_startauthsession --policy-session`
- OpenSSL tpm2 provider session support

### Verification
```bash
# Check TPM type (discrete vs firmware)
cat /sys/class/tpm/tpm0/device/description
tpm2_getcap properties-fixed | grep -i manufacturer

# If Intel/firmware TPM → no SPI exposure
# If discrete chip → needs encrypted sessions
```
