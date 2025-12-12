/**
 * @file key_vault.h
 * @brief TPM-protected key management for IoT platforms
 *
 * This module provides secure storage and usage of cryptographic keys using
 * a TPM2 (Trusted Platform Module) as the root of trust.
 *
 * ## Architecture
 *
 * The system uses a hybrid key model:
 *
 * 1. **Root Key** (in TPM): RSA key generated inside TPM, never extractable
 * 2. **User Keys** (in files): Encrypted PEM files with TPM-protected passphrases
 *
 * ```
 * ┌─────────────────────────────────────────┐
 * │              TPM2 Chip                  │
 * │  ┌─────────────────────────────────┐   │
 * │  │   Root RSA Key (0x81010002)     │   │
 * │  │   - Never leaves silicon        │   │
 * │  │   - Encrypts/decrypts           │   │
 * │  │     user passphrases            │   │
 * │  └─────────────────────────────────┘   │
 * └─────────────────────────────────────────┘
 *                    │
 *                    │ encrypts
 *                    ▼
 * ┌─────────────────────────────────────────┐
 * │         Database / Filesystem           │
 * │  ┌─────────────────────────────────┐   │
 * │  │  Encrypted passphrases          │   │
 * │  │  (useless without TPM)          │   │
 * │  └─────────────────────────────────┘   │
 * │  ┌─────────────────────────────────┐   │
 * │  │  Encrypted PEM files            │   │
 * │  │  (AES-256-CBC + passphrase)     │   │
 * │  └─────────────────────────────────┘   │
 * └─────────────────────────────────────────┘
 * ```
 *
 * ## Security Properties
 *
 * - **Hardware Binding**: Passphrases encrypted with TPM key, useless on other devices
 * - **Secure Memory**: Passphrases held in mlocked SecureBuffer, wiped after use
 * - **Minimal Exposure**: Private keys only in memory during operation (~ms)
 *
 * ## Usage
 *
 * @code
 * // Initialize vault with TPM handle
 * KeyVault vault(0x81010002, "keys/tpm_rsa_pub.pem");
 *
 * // Protect a passphrase (when user uploads key)
 * auto protected = vault.protect("user_key_A", "user's passphrase");
 * db.store(protected.serialize());
 *
 * // Later: use the protected key
 * auto signature = vault.sign_with_protected_key(
 *     protected, "keys/user_key_A.pem", data);
 * @endcode
 *
 * @see CONCEPT_DOCUMENTATION.md for full security architecture
 * @see init.sh for TPM provisioning
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <openssl/evp.h>

/**
 * @brief Auto-wiping memory buffer for sensitive data
 *
 * SecureBuffer provides a memory buffer that:
 * 1. Locks its pages in RAM (prevents swapping to disk)
 * 2. Securely wipes memory on destruction (prevents data remanence)
 *
 * ## Security Features
 *
 * - **mlock()**: Memory pages are locked in RAM, never swapped
 * - **Secure wipe**: Uses volatile pointer to prevent compiler optimization
 * - **munlock()**: Unlocks memory after wiping
 *
 * ## Usage
 *
 * @code
 * {
 *     SecureBuffer passphrase(32);
 *     // ... use passphrase.data() ...
 * }  // Automatically wiped here
 * @endcode
 *
 * @warning Move-only class. Copying would create multiple wipes of same memory.
 */
class SecureBuffer {
public:
    /**
     * @brief Allocate and lock secure memory
     * @param size Number of bytes to allocate
     */
    SecureBuffer(size_t size);

    /**
     * @brief Securely wipe and unlock memory
     */
    ~SecureBuffer();

    // Non-copyable (would cause double-wipe issues)
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Move is OK (transfers ownership)
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    /** @brief Get pointer to buffer data */
    uint8_t* data() { return data_; }

    /** @brief Get const pointer to buffer data */
    const uint8_t* data() const { return data_; }

    /** @brief Get buffer size in bytes */
    size_t size() const { return size_; }

    /**
     * @brief Explicitly wipe buffer contents
     *
     * Called automatically by destructor, but can be called early
     * to minimize the window of exposure.
     */
    void wipe();

private:
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
};

/**
 * @brief Container for TPM-encrypted passphrase
 *
 * This structure holds a passphrase that has been encrypted with the
 * TPM's RSA public key. It can be safely stored in a database or
 * filesystem - it's useless without access to the original TPM.
 *
 * ## Serialization Format
 *
 * ```
 * [key_id_len:4][key_id:N][data_len:4][encrypted_data:M]
 * ```
 *
 * ## Security
 *
 * The encrypted_data can only be decrypted by the TPM that holds the
 * corresponding private key. Cloning the storage to another device
 * will result in decryption failure.
 */
struct ProtectedPassphrase {
    /** Identifier for this key (e.g., "user_key_A") */
    std::string key_id;

    /** RSA-encrypted passphrase blob (256 bytes for RSA-2048) */
    std::vector<uint8_t> encrypted_data;

    /**
     * @brief Serialize for database storage
     * @return Binary blob suitable for storage
     */
    std::vector<uint8_t> serialize() const;

    /**
     * @brief Deserialize from database storage
     * @param data Binary blob from storage
     * @return Reconstructed ProtectedPassphrase
     * @throws std::runtime_error if data is malformed
     */
    static ProtectedPassphrase deserialize(const std::vector<uint8_t>& data);
};

/**
 * @brief TPM-protected key vault for secure passphrase management
 *
 * KeyVault provides the main interface for:
 * 1. Protecting passphrases with TPM encryption
 * 2. Loading protected keys at runtime
 * 3. Performing crypto operations with minimal exposure
 *
 * ## Initialization
 *
 * KeyVault requires:
 * - A TPM with a persistent RSA key (created by init.sh)
 * - The public key exported as PEM file
 *
 * ## Thread Safety
 *
 * KeyVault is NOT thread-safe. Use one instance per thread or
 * add external synchronization.
 *
 * ## Error Handling
 *
 * All methods throw std::runtime_error on failure with descriptive messages.
 */
class KeyVault {
public:
    /**
     * @brief Initialize KeyVault with TPM connection
     *
     * @param tpm_handle Persistent TPM handle (e.g., 0x81010002)
     * @param pubkey_pem_path Path to TPM public key PEM file
     * @param ek_ctx_path Path to Endorsement Key context file (from init.sh)
     *
     * @throws std::runtime_error if TPM connection fails
     *
     * @code
     * KeyVault vault(0x81010002, "keys/tpm_rsa_pub.pem", "keys/ek.ctx");
     * @endcode
     */
    KeyVault(uint32_t tpm_handle, const std::string& pubkey_pem_path,
             const std::string& ek_ctx_path);

    /**
     * @brief Clean up TPM connection and OpenSSL resources
     */
    ~KeyVault();

    // Non-copyable (holds TPM connection state)
    KeyVault(const KeyVault&) = delete;
    KeyVault& operator=(const KeyVault&) = delete;

    /**
     * @brief Protect a passphrase using TPM public key
     *
     * Call this when a user uploads an encrypted PEM file.
     * The passphrase is encrypted with the TPM's public key and
     * can be stored safely in a database.
     *
     * @param key_id Unique identifier for this key
     * @param passphrase The passphrase to protect
     * @return ProtectedPassphrase containing encrypted blob
     *
     * @note The original passphrase should be wiped from memory after this call
     *
     * @code
     * // User uploads key
     * auto protected = vault.protect("user_key_A", user_passphrase);
     *
     * // Store in database
     * db.store(key_id, protected.serialize());
     *
     * // Wipe original passphrase
     * explicit_bzero(&user_passphrase[0], user_passphrase.size());
     * @endcode
     */
    ProtectedPassphrase protect(const std::string& key_id,
                                const std::string& passphrase);

    /**
     * @brief Load a protected key into memory
     *
     * Decrypts the passphrase using TPM and loads the encrypted PEM file.
     *
     * @param protected_pass The encrypted passphrase from database
     * @param pem_path Path to the encrypted PEM file
     * @return EVP_PKEY* Loaded private key (caller must free with EVP_PKEY_free)
     *
     * @warning Caller is responsible for freeing the returned key!
     * @warning Key exists in memory until freed - minimize this window
     *
     * @throws std::runtime_error if decryption or PEM loading fails
     */
    EVP_PKEY* load_protected_key(const ProtectedPassphrase& protected_pass,
                                 const std::string& pem_path);

    /**
     * @brief Sign data using a protected key
     *
     * Complete sign operation with automatic cleanup:
     * 1. TPM decrypts passphrase
     * 2. Load encrypted PEM
     * 3. Wipe passphrase
     * 4. Sign data
     * 5. Free key
     *
     * @param protected_pass The encrypted passphrase from database
     * @param pem_path Path to the encrypted PEM file
     * @param data Data to sign
     * @return Signature bytes (empty on failure)
     *
     * @note Uses SHA-256 with PKCS#1 v1.5 padding
     *
     * @code
     * auto sig = vault.sign_with_protected_key(
     *     protected_pass, "keys/user_key.pem",
     *     {data.begin(), data.end()});
     * @endcode
     */
    std::vector<uint8_t> sign_with_protected_key(
        const ProtectedPassphrase& protected_pass,
        const std::string& pem_path,
        const std::vector<uint8_t>& data);

    /**
     * @brief Decrypt data using a protected key
     *
     * Complete decrypt operation with automatic cleanup:
     * 1. TPM decrypts passphrase
     * 2. Load encrypted PEM
     * 3. Wipe passphrase
     * 4. Decrypt data
     * 5. Free key
     *
     * @param protected_pass The encrypted passphrase from database
     * @param pem_path Path to the encrypted PEM file
     * @param ciphertext Data to decrypt
     * @return Plaintext bytes (empty on failure)
     *
     * @note Uses PKCS#1 v1.5 padding
     */
    std::vector<uint8_t> decrypt_with_protected_key(
        const ProtectedPassphrase& protected_pass,
        const std::string& pem_path,
        const std::vector<uint8_t>& ciphertext);

private:
    /** @brief Private implementation (PIMPL idiom) */
    class Impl;
    std::unique_ptr<Impl> impl_;
};
