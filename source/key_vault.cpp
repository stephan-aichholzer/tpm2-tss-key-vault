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
#include "tss_session.h"

#include <cstring>
#include <fstream>
#include <stdexcept>
#include <sys/mman.h>  // mlock, munlock

#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/**
 * @brief Read PCR policy index from config file
 * @param key_dir Directory containing key files
 * @return PCR index (14, 15, or 16), or -1 if no policy configured
 */
static int read_pcr_policy(const std::string& key_dir) {
    std::string policy_file = key_dir + "/pcr_policy";
    std::ifstream f(policy_file);
    if (!f.is_open()) {
        return -1;  // No PCR policy configured
    }

    int pcr_index = -1;
    f >> pcr_index;

    // Validate PCR index
    if (pcr_index < 0 || pcr_index > 23) {
        return -1;
    }

    return pcr_index;
}

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
 * - TssSession for encrypted TPM communication
 * - OpenSSL provider references (for non-TPM operations)
 */
class KeyVault::Impl {
public:
    uint32_t tpm_handle;                    ///< TPM persistent handle (e.g., 0x81010002)
    std::string pubkey_path;                ///< Path to TPM public key PEM
    std::string ek_ctx_path;                ///< Path to EK context file
    std::string key_dir;                    ///< Directory containing key files
    int pcr_index = -1;                     ///< PCR index for policy (-1 = no policy)
    std::unique_ptr<TssSession> tss_session; ///< Encrypted TPM session (EK-salted)
    OSSL_PROVIDER* default_provider = nullptr; ///< Default OpenSSL provider (for PEM ops)

    /**
     * @brief Clean up resources
     */
    ~Impl() {
        // TssSession cleans itself up via destructor
        if (default_provider) OSSL_PROVIDER_unload(default_provider);
    }

    /**
     * @brief Initialize TPM connection with EK-salted encrypted session
     *
     * Creates TssSession for secure TPM communication using the
     * Endorsement Key for session key agreement. All bus traffic
     * is AES encrypted and the session key cannot be derived by
     * an attacker sniffing the bus.
     *
     * If a PCR policy file exists (keys/pcr_policy), the session
     * will use policy-based authorization requiring the specified
     * PCR to match its provisioned value.
     */
    void init() {
        // Check for PCR policy configuration
        pcr_index = read_pcr_policy(key_dir);

        // Create EK-salted encrypted TPM session
        // Session key is derived using salt encrypted with EK
        // If pcr_index >= 0, session will require PCR policy satisfaction
        tss_session = std::make_unique<TssSession>(tpm_handle, ek_ctx_path, pcr_index);

        // Load default provider for standard crypto (PEM loading, etc.)
        default_provider = OSSL_PROVIDER_load(NULL, "default");
        if (!default_provider) {
            throw std::runtime_error("Failed to load OpenSSL default provider");
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
     * @brief Decrypt passphrase using TPM with encrypted session
     *
     * This operation happens inside the TPM hardware.
     * The private key never leaves the TPM silicon.
     *
     * **Security**: Uses TssSession which encrypts all bus communication
     * with AES-128-CFB. The decrypted passphrase travels encrypted on
     * the physical bus (SPI/LPC/I2C), protecting against bus sniffing.
     *
     * @param encrypted RSA-encrypted passphrase blob
     * @return SecureBuffer containing plaintext (will be wiped on destruction)
     */
    SecureBuffer decrypt_passphrase(const std::vector<uint8_t>& encrypted) {
        if (!tss_session || !tss_session->is_valid()) {
            throw std::runtime_error("TPM session not initialized");
        }

        // Decrypt using TssSession (encrypted session protects bus traffic)
        return tss_session->decrypt(encrypted);
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
KeyVault::KeyVault(uint32_t tpm_handle, const std::string& pubkey_pem_path,
                   const std::string& ek_ctx_path)
    : impl_(std::make_unique<Impl>()) {
    impl_->tpm_handle = tpm_handle;
    impl_->pubkey_path = pubkey_pem_path;
    impl_->ek_ctx_path = ek_ctx_path;

    // Extract key directory from ek_ctx_path (e.g., "keys/ek.ctx" -> "keys")
    size_t pos = ek_ctx_path.rfind('/');
    if (pos != std::string::npos) {
        impl_->key_dir = ek_ctx_path.substr(0, pos);
    } else {
        impl_->key_dir = ".";
    }

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
