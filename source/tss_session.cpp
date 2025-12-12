/**
 * @file tss_session.cpp
 * @brief TSS2/ESYS implementation for encrypted TPM sessions
 *
 * This implementation uses the Enhanced System API (ESYS) to establish
 * encrypted sessions with the TPM. The session encrypts all parameter
 * data on the bus using AES-128-CFB.
 *
 * ## Key Components
 *
 * - ESYS_CONTEXT: Main TSS2 context for TPM communication
 * - ESYS_TR: Transient references to TPM objects (keys, sessions)
 * - TPMT_SYM_DEF: Symmetric algorithm for session encryption (AES-128-CFB)
 * - TPMA_SESSION: Session attributes (ENCRYPT | DECRYPT flags)
 *
 * ## Session Flow
 *
 * 1. Esys_Initialize() - Connect to TPM
 * 2. Esys_TR_FromTPMPublic() - Load persistent key handle
 * 3. Esys_StartAuthSession() - Create encrypted session (salted with EK)
 * 4. Esys_TRSess_SetAttributes() - Enable encrypt/decrypt on session
 * 5. Esys_RSA_Decrypt() - Perform decrypt with session protection
 * 6. Esys_FlushContext() - Cleanup
 */

#include "tss_session.h"
#include "key_vault.h"  // For SecureBuffer

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_mu.h>

#include <stdexcept>
#include <cstring>

/**
 * @brief Helper to convert TSS2 return code to readable string
 */
static std::string tss_error(TSS2_RC rc) {
    const char* msg = Tss2_RC_Decode(rc);
    return msg ? msg : "Unknown TSS2 error";
}

/**
 * @brief EK RSA template per TCG EK Credential Profile
 * This matches what tpm2_createek uses for RSA EK
 */
static TPM2B_PUBLIC EK_RSA_TEMPLATE = {
    .size = 0,  // Will be computed
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (
            TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN |
            TPMA_OBJECT_ADMINWITHPOLICY |
            TPMA_OBJECT_RESTRICTED |
            TPMA_OBJECT_DECRYPT
        ),
        .authPolicy = {
            .size = 32,
            // Standard EK policy (PolicySecret on Endorsement hierarchy)
            .buffer = {
                0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
                0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
                0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
                0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
            }
        },
        .parameters = {
            .rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits = { .aes = 128 },
                    .mode = { .aes = TPM2_ALG_CFB }
                },
                .scheme = { .scheme = TPM2_ALG_NULL },
                .keyBits = 2048,
                .exponent = 0  // Default 65537
            }
        },
        .unique = {
            .rsa = { .size = 256, .buffer = {0} }
        }
    }
};

/**
 * @brief RAII wrapper for TSS2 resources
 */
class TssSession::Impl {
public:
    ESYS_CONTEXT* ctx = nullptr;        ///< Main ESYS context
    ESYS_TR key_handle = ESYS_TR_NONE;  ///< Loaded key reference
    ESYS_TR ek_handle = ESYS_TR_NONE;   ///< Endorsement Key reference
    ESYS_TR session = ESYS_TR_NONE;     ///< Encrypted session
    bool valid = false;

    /**
     * @brief Initialize TPM connection with EK-salted encrypted session
     */
    void init(uint32_t persistent_handle, const std::string& /* ek_ctx_path - unused */) {
        TSS2_RC rc;

        // -----------------------------------------------------------------
        // Step 1: Initialize ESYS context (connects to TPM via TCTI)
        // -----------------------------------------------------------------
        // NULL TCTI = auto-detect (/dev/tpmrm0 or tabrmd)
        rc = Esys_Initialize(&ctx, nullptr, nullptr);
        if (rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("Esys_Initialize failed: " + tss_error(rc));
        }

        // -----------------------------------------------------------------
        // Step 2: Load persistent key handle into ESYS transient reference
        // -----------------------------------------------------------------
        rc = Esys_TR_FromTPMPublic(
            ctx,
            persistent_handle,      // e.g., 0x81010002
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &key_handle
        );
        if (rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("Esys_TR_FromTPMPublic failed: " + tss_error(rc));
        }

        // -----------------------------------------------------------------
        // Step 3: Create Endorsement Key for session salting
        // -----------------------------------------------------------------
        // We create the EK directly using Esys_CreatePrimary rather than
        // loading from file (tpm2-tools uses incompatible context format).
        // The EK is deterministic - same seed always produces same key.
        TPM2B_SENSITIVE_CREATE inSensitive = { .size = 0 };
        TPM2B_DATA outsideInfo = { .size = 0 };
        TPML_PCR_SELECTION creationPCR = { .count = 0 };

        rc = Esys_CreatePrimary(
            ctx,
            ESYS_TR_RH_ENDORSEMENT,  // Endorsement hierarchy
            ESYS_TR_PASSWORD,        // No auth needed for EK creation
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &inSensitive,
            &EK_RSA_TEMPLATE,
            &outsideInfo,
            &creationPCR,
            &ek_handle,
            nullptr,                 // outPublic
            nullptr,                 // creationData
            nullptr,                 // creationHash
            nullptr                  // creationTicket
        );
        if (rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("Esys_CreatePrimary (EK) failed: " + tss_error(rc));
        }

        // -----------------------------------------------------------------
        // Step 4: Start SALTED encrypted session using EK
        // -----------------------------------------------------------------
        // Symmetric algorithm for session encryption
        TPMT_SYM_DEF symmetric = {
            .algorithm = TPM2_ALG_AES,
            .keyBits = { .aes = 128 },
            .mode = { .aes = TPM2_ALG_CFB }
        };

        // Start HMAC session with encryption, SALTED with EK
        // The salt is encrypted with EK public key - only TPM can decrypt
        // This prevents bus sniffers from deriving the session key
        rc = Esys_StartAuthSession(
            ctx,
            ek_handle,              // tpmKey = EK for salted session (!)
            ESYS_TR_NONE,           // bind (none)
            ESYS_TR_NONE,           // shandle1
            ESYS_TR_NONE,           // shandle2
            ESYS_TR_NONE,           // shandle3
            nullptr,                // nonceCaller (auto-generated)
            TPM2_SE_HMAC,           // session type
            &symmetric,             // AES-128-CFB for encryption
            TPM2_ALG_SHA256,        // hash algorithm
            &session
        );
        if (rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("Esys_StartAuthSession failed: " + tss_error(rc));
        }

        // -----------------------------------------------------------------
        // Step 5: Enable encryption on session
        // -----------------------------------------------------------------
        // TPMA_SESSION_DECRYPT = encrypt commands TO TPM
        // TPMA_SESSION_ENCRYPT = encrypt responses FROM TPM
        TPMA_SESSION attrs = TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT
                           | TPMA_SESSION_CONTINUESESSION;

        rc = Esys_TRSess_SetAttributes(ctx, session, attrs, 0xFF);
        if (rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("Esys_TRSess_SetAttributes failed: " + tss_error(rc));
        }

        valid = true;
    }

    /**
     * @brief Cleanup TPM resources
     */
    ~Impl() {
        if (ctx) {
            if (session != ESYS_TR_NONE) {
                Esys_FlushContext(ctx, session);
            }
            if (ek_handle != ESYS_TR_NONE) {
                Esys_FlushContext(ctx, ek_handle);
            }
            // Note: Don't flush persistent key handle, just the transient reference
            Esys_Finalize(&ctx);
        }
    }

    /**
     * @brief RSA decrypt with encrypted session
     */
    SecureBuffer do_decrypt(const std::vector<uint8_t>& ciphertext) {
        if (!valid) {
            throw std::runtime_error("TssSession not initialized");
        }

        TSS2_RC rc;

        // Prepare ciphertext as TPM2B structure
        TPM2B_PUBLIC_KEY_RSA cipher_in = { 0 };
        if (ciphertext.size() > sizeof(cipher_in.buffer)) {
            throw std::runtime_error("Ciphertext too large for RSA-2048");
        }
        cipher_in.size = static_cast<uint16_t>(ciphertext.size());
        std::memcpy(cipher_in.buffer, ciphertext.data(), ciphertext.size());

        // RSA decrypt scheme (PKCS1 v1.5)
        TPMT_RSA_DECRYPT scheme = {
            .scheme = TPM2_ALG_RSAES,  // PKCS1 v1.5 padding
            .details = { 0 }
        };

        // Output buffer (allocated by ESYS)
        TPM2B_PUBLIC_KEY_RSA* plaintext = nullptr;

        // -----------------------------------------------------------------
        // Perform RSA decrypt with encrypted session
        // -----------------------------------------------------------------
        // The session handle ensures:
        // - cipher_in is encrypted on bus TO TPM (TPMA_SESSION_DECRYPT)
        // - plaintext is encrypted on bus FROM TPM (TPMA_SESSION_ENCRYPT)
        rc = Esys_RSA_Decrypt(
            ctx,
            key_handle,             // Key to use
            session,                // Session with encryption (!)
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &cipher_in,             // Ciphertext
            &scheme,                // PKCS1 v1.5
            nullptr,                // label (none)
            &plaintext              // Output
        );

        if (rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("Esys_RSA_Decrypt failed: " + tss_error(rc));
        }

        // Copy result to SecureBuffer before freeing ESYS allocation
        SecureBuffer result(plaintext->size);
        std::memcpy(result.data(), plaintext->buffer, plaintext->size);

        // Wipe and free ESYS-allocated buffer
        volatile uint8_t* p = plaintext->buffer;
        for (size_t i = 0; i < plaintext->size; ++i) {
            p[i] = 0;
        }
        Esys_Free(plaintext);

        return result;
    }
};

// =============================================================================
// Public API
// =============================================================================

TssSession::TssSession(uint32_t key_handle, const std::string& ek_ctx_path)
    : impl_(std::make_unique<Impl>()) {
    impl_->init(key_handle, ek_ctx_path);
}

TssSession::~TssSession() = default;

TssSession::TssSession(TssSession&& other) noexcept = default;
TssSession& TssSession::operator=(TssSession&& other) noexcept = default;

SecureBuffer TssSession::decrypt(const std::vector<uint8_t>& ciphertext) {
    return impl_->do_decrypt(ciphertext);
}

bool TssSession::is_valid() const {
    return impl_ && impl_->valid;
}
