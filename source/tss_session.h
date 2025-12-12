/**
 * @file tss_session.h
 * @brief TPM2 encrypted session handler using TSS2/ESYS
 *
 * This module provides secure TPM communication with encrypted sessions.
 * All command parameters and responses are AES-encrypted on the bus,
 * protecting against physical bus sniffing attacks (SPI/I2C/LPC).
 *
 * ## Security Model
 *
 * Without encrypted session:
 *   Application ──[plaintext]──► TPM
 *
 * With encrypted session (this module):
 *   Application ──[AES-128-CFB encrypted]──► TPM
 *
 * ## Session Key Derivation
 *
 * 1. TSS generates random salt
 * 2. Salt encrypted with TPM's Endorsement Key (EK) public key
 * 3. TPM decrypts salt with EK private (never leaves TPM)
 * 4. Both sides derive sessionKey = KDF(salt || nonces)
 * 5. All subsequent data AES encrypted with sessionKey
 *
 * @see CONCEPT_DOCUMENTATION.md for full security architecture
 */

#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <string>

// Forward declare SecureBuffer to avoid circular dependency
class SecureBuffer;

/**
 * @class TssSession
 * @brief Encapsulates TPM2 operations with encrypted session protection
 *
 * Provides RSA decrypt operations using TPM hardware with all bus
 * communication encrypted. This protects against physical attacks
 * like SPI bus sniffing.
 *
 * Uses the Endorsement Key (EK) to establish a salted session where
 * the session key derivation is protected - an attacker sniffing the
 * bus cannot derive the session key even if they see all traffic.
 *
 * Usage:
 * @code
 *   TssSession session(0x81010002, "keys/ek.ctx");
 *   SecureBuffer plaintext = session.decrypt(ciphertext);
 * @endcode
 *
 * Thread Safety: NOT thread-safe. Create one instance per thread.
 */
class TssSession {
public:
    /**
     * @brief Initialize TPM connection with EK-salted encrypted session
     *
     * Connects to TPM via /dev/tpmrm0, loads the specified key and EK,
     * and establishes an encrypted session using the Endorsement Key
     * for secure key agreement.
     *
     * @param key_handle Persistent TPM handle (e.g., 0x81010002)
     * @param ek_ctx_path Path to EK context file from init.sh (e.g., "keys/ek.ctx")
     * @throws std::runtime_error if TPM connection or session setup fails
     */
    TssSession(uint32_t key_handle, const std::string& ek_ctx_path);

    /**
     * @brief Cleanup TPM resources
     *
     * Flushes session and key contexts, closes TPM connection.
     */
    ~TssSession();

    // Non-copyable (TPM session state cannot be duplicated)
    TssSession(const TssSession&) = delete;
    TssSession& operator=(const TssSession&) = delete;

    // Movable
    TssSession(TssSession&& other) noexcept;
    TssSession& operator=(TssSession&& other) noexcept;

    /**
     * @brief RSA decrypt using TPM with encrypted session
     *
     * Decryption happens inside TPM silicon. The decrypted result
     * travels back encrypted on the bus (AES-128-CFB), then is
     * decrypted by TSS library before being placed in SecureBuffer.
     *
     * @param ciphertext RSA-PKCS1 encrypted data (typically 256 bytes for RSA-2048)
     * @return SecureBuffer containing plaintext (mlock'd, auto-wiped)
     * @throws std::runtime_error if decryption fails
     */
    SecureBuffer decrypt(const std::vector<uint8_t>& ciphertext);

    /**
     * @brief Check if session is valid and connected
     * @return true if TPM connection and session are active
     */
    bool is_valid() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
