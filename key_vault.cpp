/**
 * @file key_vault.cpp
 * @brief Implementation of TPM-protected key vault
 *
 * This file implements the KeyVault class which provides secure storage
 * and usage of cryptographic keys using TPM2 hardware.
 *
 * ## Implementation Details
 *
 * ### OpenSSL Provider Architecture
 *
 * We use OpenSSL 3.x provider model:
 * - **tpm2 provider**: For operations involving TPM key (decrypt passphrase)
 * - **default provider**: For standard crypto operations
 *
 * When encrypting passphrases, we use a SEPARATE library context with only
 * the default provider to avoid TPM provider interference.
 *
 * ### Memory Security
 *
 * - SecureBuffer: mlock'd memory that is wiped on destruction
 * - Passphrase copies are wiped immediately after use
 * - EVP_PKEY is freed as soon as operation completes
 *
 * @see key_vault.h for API documentation
 */

#include "key_vault.h"

#include <cstring>
#include <stdexcept>
#include <sys/mman.h>  // mlock, munlock

#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// =============================================================================
// SecureBuffer Implementation
// =============================================================================

/**
 * @brief Allocate secure memory buffer
 *
 * Memory is:
 * 1. Allocated with new[]
 * 2. Locked in RAM with mlock() to prevent swapping
 * 3. Zeroed initially
 */
SecureBuffer::SecureBuffer(size_t size) : size_(size) {
    if (size_ > 0) {
        data_ = new uint8_t[size_];

        // Lock memory pages to prevent swapping to disk
        // This may fail without CAP_IPC_LOCK, but we try anyway
        mlock(data_, size_);

        // Initialize to zero
        std::memset(data_, 0, size_);
    }
}

/**
 * @brief Destroy buffer with secure wipe
 */
SecureBuffer::~SecureBuffer() {
    wipe();
}

/**
 * @brief Move constructor - transfers ownership
 */
SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    // Null out source to prevent double-free/double-wipe
    other.data_ = nullptr;
    other.size_ = 0;
}

/**
 * @brief Move assignment - transfers ownership
 */
SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        // Wipe current contents first
        wipe();

        // Take ownership
        data_ = other.data_;
        size_ = other.size_;

        // Null out source
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

/**
 * @brief Securely wipe buffer contents
 *
 * Uses volatile pointer to prevent compiler from optimizing away the writes.
 * This is critical - without volatile, the compiler might remove the loop
 * since the memory is about to be freed anyway.
 */
void SecureBuffer::wipe() {
    if (data_) {
        // Volatile prevents compiler optimization
        // The compiler MUST perform these writes
        volatile uint8_t* p = data_;
        for (size_t i = 0; i < size_; ++i) {
            p[i] = 0;
        }

        // Unlock memory (allows swapping again, but we're about to free)
        munlock(data_, size_);

        // Free memory
        delete[] data_;
        data_ = nullptr;
        size_ = 0;
    }
}

// =============================================================================
// ProtectedPassphrase Serialization
// =============================================================================

/**
 * @brief Serialize to binary format for database storage
 *
 * Format: [key_id_len:4][key_id:N][data_len:4][encrypted_data:M]
 *
 * Uses little-endian byte order (native on x86/ARM).
 */
std::vector<uint8_t> ProtectedPassphrase::serialize() const {
    std::vector<uint8_t> result;

    uint32_t id_len = static_cast<uint32_t>(key_id.size());
    uint32_t data_len = static_cast<uint32_t>(encrypted_data.size());

    // Reserve exact size needed
    result.resize(4 + id_len + 4 + data_len);
    uint8_t* p = result.data();

    // Write key_id length and data
    std::memcpy(p, &id_len, 4);
    p += 4;
    std::memcpy(p, key_id.data(), id_len);
    p += id_len;

    // Write encrypted_data length and data
    std::memcpy(p, &data_len, 4);
    p += 4;
    std::memcpy(p, encrypted_data.data(), data_len);

    return result;
}

/**
 * @brief Deserialize from binary format
 *
 * @throws std::runtime_error if data is too short or malformed
 */
ProtectedPassphrase ProtectedPassphrase::deserialize(const std::vector<uint8_t>& data) {
    // Minimum size: 4 (id_len) + 0 (id) + 4 (data_len) + 0 (data) = 8
    if (data.size() < 8) {
        throw std::runtime_error("Invalid protected passphrase data: too short");
    }

    const uint8_t* p = data.data();
    uint32_t id_len, data_len;

    // Read key_id
    std::memcpy(&id_len, p, 4);
    p += 4;

    if (data.size() < 8 + id_len) {
        throw std::runtime_error("Invalid protected passphrase data: truncated key_id");
    }

    ProtectedPassphrase result;
    result.key_id = std::string(reinterpret_cast<const char*>(p), id_len);
    p += id_len;

    // Read encrypted_data
    std::memcpy(&data_len, p, 4);
    p += 4;

    if (data.size() < 8 + id_len + data_len) {
        throw std::runtime_error("Invalid protected passphrase data: truncated encrypted_data");
    }

    result.encrypted_data.assign(p, p + data_len);
    return result;
}

// =============================================================================
// KeyVault Private Implementation
// =============================================================================

/**
 * @brief Private implementation class (PIMPL idiom)
 *
 * Holds:
 * - TPM handle and connection state
 * - OpenSSL provider references
 * - TPM key reference (EVP_PKEY backed by TPM)
 */
class KeyVault::Impl {
public:
    uint32_t tpm_handle;                    ///< TPM persistent handle (e.g., 0x81010002)
    std::string pubkey_path;                ///< Path to TPM public key PEM
    OSSL_PROVIDER* tpm2_provider = nullptr; ///< TPM2 OpenSSL provider
    OSSL_PROVIDER* default_provider = nullptr; ///< Default OpenSSL provider
    EVP_PKEY* tpm_key = nullptr;            ///< Reference to TPM key (not actual key!)

    /**
     * @brief Clean up OpenSSL resources
     */
    ~Impl() {
        if (tpm_key) EVP_PKEY_free(tpm_key);
        if (tpm2_provider) OSSL_PROVIDER_unload(tpm2_provider);
        if (default_provider) OSSL_PROVIDER_unload(default_provider);
    }

    /**
     * @brief Initialize TPM connection and load providers
     *
     * Loads both tpm2 and default OpenSSL providers, then loads
     * a reference to the TPM key via the STORE API.
     */
    void init() {
        // Load TPM2 provider for hardware crypto operations
        tpm2_provider = OSSL_PROVIDER_load(NULL, "tpm2");
        if (!tpm2_provider) {
            throw std::runtime_error("Failed to load TPM2 provider. "
                                     "Is tpm2-openssl installed?");
        }

        // Load default provider for standard crypto
        default_provider = OSSL_PROVIDER_load(NULL, "default");

        // Build TPM handle URI (e.g., "handle:0x81010002")
        char handle_uri[64];
        snprintf(handle_uri, sizeof(handle_uri), "handle:0x%08x", tpm_handle);

        // Open STORE to load key from TPM
        OSSL_STORE_CTX* store = OSSL_STORE_open(handle_uri, NULL, NULL, NULL, NULL);
        if (!store) {
            throw std::runtime_error("Failed to open TPM key store. "
                                     "Is the TPM key at the specified handle?");
        }

        // Load key from store
        while (!OSSL_STORE_eof(store)) {
            OSSL_STORE_INFO* info = OSSL_STORE_load(store);
            if (!info) continue;

            if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
                tpm_key = OSSL_STORE_INFO_get1_PKEY(info);
            }
            OSSL_STORE_INFO_free(info);

            if (tpm_key) break;
        }
        OSSL_STORE_close(store);

        if (!tpm_key) {
            throw std::runtime_error("Failed to load TPM key from handle");
        }
    }

    /**
     * @brief Encrypt passphrase using TPM public key
     *
     * Uses a SEPARATE OpenSSL library context with only the default provider.
     * This is necessary because the TPM provider doesn't support encryption
     * (only the TPM can decrypt, not encrypt with its own key).
     *
     * @param passphrase Plaintext passphrase to encrypt
     * @return RSA-encrypted blob (256 bytes for RSA-2048)
     */
    std::vector<uint8_t> encrypt_passphrase(const std::string& passphrase) {
        std::vector<uint8_t> result;

        // Create isolated library context with only default provider
        // This prevents TPM provider from interfering with public key operations
        OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER* defprov = OSSL_PROVIDER_load(libctx, "default");

        // Load public key from PEM file
        FILE* fp = fopen(pubkey_path.c_str(), "r");
        if (!fp) {
            OSSL_PROVIDER_unload(defprov);
            OSSL_LIB_CTX_free(libctx);
            throw std::runtime_error("Cannot open public key file: " + pubkey_path);
        }

        EVP_PKEY* pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        fclose(fp);

        if (!pubkey) {
            OSSL_PROVIDER_unload(defprov);
            OSSL_LIB_CTX_free(libctx);
            throw std::runtime_error("Cannot read public key from PEM");
        }

        // Create encryption context in isolated library context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pubkey, NULL);
        if (!ctx ||
            EVP_PKEY_encrypt_init(ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
            EVP_PKEY_free(pubkey);
            OSSL_PROVIDER_unload(defprov);
            OSSL_LIB_CTX_free(libctx);
            throw std::runtime_error("Encryption initialization failed");
        }

        // Determine output size
        size_t out_len = 0;
        const uint8_t* in_data = reinterpret_cast<const uint8_t*>(passphrase.data());

        if (EVP_PKEY_encrypt(ctx, NULL, &out_len, in_data, passphrase.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pubkey);
            OSSL_PROVIDER_unload(defprov);
            OSSL_LIB_CTX_free(libctx);
            throw std::runtime_error("Encryption length check failed");
        }

        // Perform encryption
        result.resize(out_len);
        if (EVP_PKEY_encrypt(ctx, result.data(), &out_len, in_data, passphrase.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pubkey);
            OSSL_PROVIDER_unload(defprov);
            OSSL_LIB_CTX_free(libctx);
            throw std::runtime_error("Encryption failed");
        }
        result.resize(out_len);

        // Cleanup
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        OSSL_PROVIDER_unload(defprov);
        OSSL_LIB_CTX_free(libctx);

        return result;
    }

    /**
     * @brief Decrypt passphrase using TPM
     *
     * This operation happens inside the TPM hardware.
     * The private key never leaves the TPM silicon.
     *
     * @param encrypted RSA-encrypted passphrase blob
     * @return SecureBuffer containing plaintext (will be wiped on destruction)
     */
    SecureBuffer decrypt_passphrase(const std::vector<uint8_t>& encrypted) {
        // Create context using TPM-backed key
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(tpm_key, NULL);
        if (!ctx) {
            throw std::runtime_error("Cannot create TPM decrypt context");
        }

        // Initialize decryption with PKCS#1 v1.5 padding
        if (EVP_PKEY_decrypt_init(ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("TPM decrypt initialization failed");
        }

        // Determine output size
        size_t out_len = 0;
        if (EVP_PKEY_decrypt(ctx, NULL, &out_len, encrypted.data(), encrypted.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("TPM decrypt length check failed");
        }

        // Decrypt into SecureBuffer
        SecureBuffer result(out_len);
        if (EVP_PKEY_decrypt(ctx, result.data(), &out_len,
                             encrypted.data(), encrypted.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("TPM decryption failed");
        }

        EVP_PKEY_CTX_free(ctx);

        // Handle case where actual output is shorter than buffer
        if (out_len < result.size()) {
            SecureBuffer resized(out_len);
            std::memcpy(resized.data(), result.data(), out_len);
            return resized;
        }

        return result;
    }

    /**
     * @brief Load encrypted PEM file using passphrase
     *
     * @param pem_path Path to AES-256-CBC encrypted PEM file
     * @param passphrase Decrypted passphrase in SecureBuffer
     * @return EVP_PKEY* Loaded private key (caller must free!)
     */
    EVP_PKEY* load_encrypted_pem(const std::string& pem_path,
                                  const SecureBuffer& passphrase) {
        FILE* fp = fopen(pem_path.c_str(), "r");
        if (!fp) {
            throw std::runtime_error("Cannot open PEM file: " + pem_path);
        }

        // Create null-terminated passphrase string for OpenSSL
        // This is a necessary evil - OpenSSL requires C string
        std::vector<char> pass_cstr(passphrase.size() + 1);
        std::memcpy(pass_cstr.data(), passphrase.data(), passphrase.size());
        pass_cstr[passphrase.size()] = '\0';

        // Load encrypted private key
        EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, pass_cstr.data());
        fclose(fp);

        // IMMEDIATELY wipe the passphrase copy
        volatile char* p = pass_cstr.data();
        for (size_t i = 0; i < pass_cstr.size(); ++i) {
            p[i] = 0;
        }

        if (!pkey) {
            unsigned long err = ERR_get_error();
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            throw std::runtime_error(std::string("Cannot decrypt PEM file: ") + buf);
        }

        return pkey;
    }
};

// =============================================================================
// KeyVault Public Methods
// =============================================================================

/**
 * @brief Initialize KeyVault with TPM connection
 */
KeyVault::KeyVault(uint32_t tpm_handle, const std::string& pubkey_pem_path)
    : impl_(std::make_unique<Impl>()) {
    impl_->tpm_handle = tpm_handle;
    impl_->pubkey_path = pubkey_pem_path;
    impl_->init();
}

KeyVault::~KeyVault() = default;

/**
 * @brief Protect passphrase with TPM public key
 */
ProtectedPassphrase KeyVault::protect(const std::string& key_id,
                                       const std::string& passphrase) {
    ProtectedPassphrase result;
    result.key_id = key_id;
    result.encrypted_data = impl_->encrypt_passphrase(passphrase);
    return result;
}

/**
 * @brief Load protected key (caller must free!)
 */
EVP_PKEY* KeyVault::load_protected_key(const ProtectedPassphrase& protected_pass,
                                        const std::string& pem_path) {
    // Step 1: Decrypt passphrase using TPM
    SecureBuffer passphrase = impl_->decrypt_passphrase(protected_pass.encrypted_data);

    // Step 2: Load encrypted PEM using passphrase
    EVP_PKEY* pkey = impl_->load_encrypted_pem(pem_path, passphrase);

    // Step 3: SecureBuffer destructor wipes passphrase automatically

    return pkey;
}

/**
 * @brief Sign data with protected key
 *
 * Complete operation flow:
 * 1. TPM decrypts passphrase (hardware operation)
 * 2. Passphrase in SecureBuffer (mlocked)
 * 3. OpenSSL loads encrypted PEM
 * 4. Passphrase wiped immediately
 * 5. Sign operation performed
 * 6. Key freed from memory
 */
std::vector<uint8_t> KeyVault::sign_with_protected_key(
    const ProtectedPassphrase& protected_pass,
    const std::string& pem_path,
    const std::vector<uint8_t>& data) {

    std::vector<uint8_t> signature;

    // Load key (automatically decrypts passphrase via TPM)
    EVP_PKEY* pkey = load_protected_key(protected_pass, pem_path);
    if (!pkey) return signature;

    // Perform sign operation
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        // Initialize signing with SHA-256
        if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
            EVP_DigestSignUpdate(ctx, data.data(), data.size()) == 1) {

            // Determine signature size
            size_t sig_len = 0;
            EVP_DigestSignFinal(ctx, NULL, &sig_len);
            signature.resize(sig_len);

            // Create signature
            if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) == 1) {
                signature.resize(sig_len);
            } else {
                signature.clear();
            }
        }
        EVP_MD_CTX_free(ctx);
    }

    // CRITICAL: Free key immediately to minimize exposure window
    EVP_PKEY_free(pkey);

    return signature;
}

/**
 * @brief Decrypt data with protected key
 *
 * Same flow as sign_with_protected_key but for RSA decryption.
 */
std::vector<uint8_t> KeyVault::decrypt_with_protected_key(
    const ProtectedPassphrase& protected_pass,
    const std::string& pem_path,
    const std::vector<uint8_t>& ciphertext) {

    std::vector<uint8_t> plaintext;

    // Load key (automatically decrypts passphrase via TPM)
    EVP_PKEY* pkey = load_protected_key(protected_pass, pem_path);
    if (!pkey) return plaintext;

    // Perform decrypt operation
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx) {
        if (EVP_PKEY_decrypt_init(ctx) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1) {

            // Determine output size
            size_t out_len = 0;
            if (EVP_PKEY_decrypt(ctx, NULL, &out_len,
                                 ciphertext.data(), ciphertext.size()) == 1) {
                plaintext.resize(out_len);

                // Decrypt
                if (EVP_PKEY_decrypt(ctx, plaintext.data(), &out_len,
                                     ciphertext.data(), ciphertext.size()) == 1) {
                    plaintext.resize(out_len);
                } else {
                    plaintext.clear();
                }
            }
        }
        EVP_PKEY_CTX_free(ctx);
    }

    // CRITICAL: Free key immediately to minimize exposure window
    EVP_PKEY_free(pkey);

    return plaintext;
}
