#include <iostream>
#include <vector>
#include <string>
#include <cstring>

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/err.h>
#include <openssl/pem.h>

// TPM persistent handle (created with tpm2_evictcontrol)
#define TPM_KEY_HANDLE "handle:0x81010002"
// Public key file (exported with tpm2_readpublic)
#define PUBLIC_KEY_FILE "keys/tpm_rsa_pub.pem"

void print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (auto b : data) {
        printf("%02x", b);
    }
    std::cout << std::endl;
}

void print_openssl_error() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << "OpenSSL error: " << buf << std::endl;
    }
}

// Load TPM key via OpenSSL STORE API
EVP_PKEY* load_tpm_key() {
    OSSL_STORE_CTX* store = OSSL_STORE_open(TPM_KEY_HANDLE, NULL, NULL, NULL, NULL);
    if (!store) {
        std::cerr << "Failed to open TPM key store" << std::endl;
        print_openssl_error();
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    while (!OSSL_STORE_eof(store)) {
        OSSL_STORE_INFO* info = OSSL_STORE_load(store);
        if (!info) continue;

        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
        }
        OSSL_STORE_INFO_free(info);
        if (pkey) break;
    }
    OSSL_STORE_close(store);

    return pkey;
}

// Sign data using TPM key (PKCS#1 v1.5 with SHA-256)
std::vector<uint8_t> tpm_sign(EVP_PKEY* pkey, const std::string& data) {
    std::vector<uint8_t> signature;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return signature;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        std::cerr << "DigestSignInit failed" << std::endl;
        print_openssl_error();
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) != 1) {
        std::cerr << "DigestSignUpdate failed" << std::endl;
        print_openssl_error();
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // Get signature length
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &sig_len) != 1) {
        std::cerr << "DigestSignFinal (get length) failed" << std::endl;
        print_openssl_error();
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    signature.resize(sig_len);
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) != 1) {
        std::cerr << "DigestSignFinal failed" << std::endl;
        print_openssl_error();
        signature.clear();
    }

    EVP_MD_CTX_free(ctx);
    return signature;
}

// Decrypt using TPM key (PKCS#1 v1.5 padding)
std::vector<uint8_t> tpm_decrypt(EVP_PKEY* pkey, const std::vector<uint8_t>& ciphertext) {
    std::vector<uint8_t> plaintext;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) return plaintext;

    if (EVP_PKEY_decrypt_init(ctx) != 1) {
        std::cerr << "decrypt_init failed" << std::endl;
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return plaintext;
    }

    // Set PKCS#1 v1.5 padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
        std::cerr << "set_rsa_padding failed" << std::endl;
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return plaintext;
    }

    // Get plaintext length
    size_t out_len = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &out_len, ciphertext.data(), ciphertext.size()) != 1) {
        std::cerr << "decrypt (get length) failed" << std::endl;
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return plaintext;
    }

    plaintext.resize(out_len);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &out_len, ciphertext.data(), ciphertext.size()) != 1) {
        std::cerr << "decrypt failed" << std::endl;
        print_openssl_error();
        plaintext.clear();
    } else {
        plaintext.resize(out_len);
    }

    EVP_PKEY_CTX_free(ctx);
    return plaintext;
}

// Encrypt using public key PEM file (simulates external party - uses default provider only)
std::vector<uint8_t> encrypt_with_pubkey_file(const char* pubkey_file, const std::string& data) {
    std::vector<uint8_t> ciphertext;

    // Create separate library context with only default provider (no TPM)
    OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();
    if (!libctx) return ciphertext;

    OSSL_PROVIDER* defprov = OSSL_PROVIDER_load(libctx, "default");
    if (!defprov) {
        OSSL_LIB_CTX_free(libctx);
        return ciphertext;
    }

    // Load public key in this context
    FILE* fp = fopen(pubkey_file, "r");
    if (!fp) {
        std::cerr << "Cannot open public key file: " << pubkey_file << std::endl;
        OSSL_PROVIDER_unload(defprov);
        OSSL_LIB_CTX_free(libctx);
        return ciphertext;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        print_openssl_error();
        OSSL_PROVIDER_unload(defprov);
        OSSL_LIB_CTX_free(libctx);
        return ciphertext;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(defprov);
        OSSL_LIB_CTX_free(libctx);
        return ciphertext;
    }

    if (EVP_PKEY_encrypt_init(ctx) != 1) {
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(defprov);
        OSSL_LIB_CTX_free(libctx);
        return ciphertext;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(defprov);
        OSSL_LIB_CTX_free(libctx);
        return ciphertext;
    }

    size_t out_len = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &out_len,
                         reinterpret_cast<const uint8_t*>(data.data()), data.size()) != 1) {
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(defprov);
        OSSL_LIB_CTX_free(libctx);
        return ciphertext;
    }

    ciphertext.resize(out_len);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &out_len,
                         reinterpret_cast<const uint8_t*>(data.data()), data.size()) != 1) {
        print_openssl_error();
        ciphertext.clear();
    } else {
        ciphertext.resize(out_len);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(defprov);
    OSSL_LIB_CTX_free(libctx);
    return ciphertext;
}

// Verify signature using public key
bool verify_signature(EVP_PKEY* pkey, const std::string& data, const std::vector<uint8_t>& signature) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    bool result = false;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) == 1 &&
        EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1) {
        result = true;
    }

    EVP_MD_CTX_free(ctx);
    return result;
}

int main() {
    std::cout << "=== TPM2 OpenSSL Example ===" << std::endl << std::endl;

    // Load TPM2 and default providers
    OSSL_PROVIDER* tpm2_prov = OSSL_PROVIDER_load(NULL, "tpm2");
    OSSL_PROVIDER* default_prov = OSSL_PROVIDER_load(NULL, "default");

    if (!tpm2_prov) {
        std::cerr << "Failed to load TPM2 provider" << std::endl;
        print_openssl_error();
        return 1;
    }
    std::cout << "TPM2 provider loaded" << std::endl;

    // Load key from TPM
    EVP_PKEY* pkey = load_tpm_key();
    if (!pkey) {
        std::cerr << "Failed to load TPM key" << std::endl;
        return 1;
    }
    std::cout << "TPM key loaded from " << TPM_KEY_HANDLE << std::endl << std::endl;

    // === SIGNING EXAMPLE ===
    std::cout << "--- Signing Example ---" << std::endl;
    std::string message = "Hello TPM! This message will be signed.";
    std::cout << "Message: \"" << message << "\"" << std::endl;

    auto signature = tpm_sign(pkey, message);
    if (signature.empty()) {
        std::cerr << "Signing failed" << std::endl;
        return 1;
    }
    print_hex("Signature", signature);

    // Verify
    bool valid = verify_signature(pkey, message, signature);
    std::cout << "Signature valid: " << (valid ? "YES" : "NO") << std::endl << std::endl;

    // === DECRYPTION EXAMPLE ===
    std::cout << "--- Decryption Example ---" << std::endl;
    std::string secret = "MySecretPassphrase123!";
    std::cout << "Original secret: \"" << secret << "\"" << std::endl;

    // Encrypt with public key (simulating external sender)
    auto ciphertext = encrypt_with_pubkey_file(PUBLIC_KEY_FILE, secret);
    if (ciphertext.empty()) {
        std::cerr << "Encryption failed" << std::endl;
        return 1;
    }
    print_hex("Ciphertext", ciphertext);

    // Decrypt with TPM (private key operation)
    auto decrypted = tpm_decrypt(pkey, ciphertext);
    if (decrypted.empty()) {
        std::cerr << "Decryption failed" << std::endl;
        return 1;
    }

    std::string decrypted_str(decrypted.begin(), decrypted.end());
    std::cout << "Decrypted: \"" << decrypted_str << "\"" << std::endl;
    std::cout << "Match: " << (secret == decrypted_str ? "YES" : "NO") << std::endl;

    // Cleanup
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(tpm2_prov);
    OSSL_PROVIDER_unload(default_prov);

    std::cout << std::endl << "=== Done ===" << std::endl;
    return 0;
}
