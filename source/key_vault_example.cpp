#include <iostream>
#include <fstream>
#include "key_vault.h"
#include "process_hardening.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

// Helper: Print hex
void print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < std::min(data.size(), size_t(32)); ++i) {
        printf("%02x", data[i]);
    }
    if (data.size() > 32) std::cout << "...";
    std::cout << std::endl;
}

// Helper: Create test encrypted PEM
void create_test_pem(const std::string& path, const std::string& passphrase) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    FILE* fp = fopen(path.c_str(), "w");
    PEM_write_PrivateKey(fp, pkey, EVP_aes_256_cbc(),
                         (unsigned char*)passphrase.c_str(),
                         passphrase.size(), NULL, NULL);
    fclose(fp);
    EVP_PKEY_free(pkey);

    std::cout << "   Created: " << path << std::endl;
}

// Helper: Check if file exists
bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

int main() {
    std::cout << "=== KeyVault Example (Hardened) ===" << std::endl;
    std::cout << "TPM-protected passphrase storage with process hardening\n" << std::endl;

    const uint32_t TPM_HANDLE = 0x81010002;
    const std::string PUBKEY_PATH = "keys/tpm_rsa_pub.pem";
    const std::string EK_CTX_PATH = "keys/ek.ctx";

    // =========================================================================
    // Check required files exist BEFORE doing anything
    // =========================================================================
    bool missing = false;
    if (!file_exists(PUBKEY_PATH)) {
        std::cerr << "ERROR: Missing " << PUBKEY_PATH << std::endl;
        missing = true;
    }
    if (!file_exists(EK_CTX_PATH)) {
        std::cerr << "ERROR: Missing " << EK_CTX_PATH << std::endl;
        missing = true;
    }
    if (missing) {
        std::cerr << std::endl;
        std::cerr << "Required files not found. Make sure you:" << std::endl;
        std::cerr << "  1. Run from the project root directory (where keys/ exists)" << std::endl;
        std::cerr << "  2. Have run ./init.sh to provision the TPM" << std::endl;
        std::cerr << std::endl;
        std::cerr << "Example:" << std::endl;
        std::cerr << "  cd /path/to/tpm2" << std::endl;
        std::cerr << "  ./init.sh" << std::endl;
        std::cerr << "  ./source/build/key_vault_example" << std::endl;
        return 1;
    }

    // =========================================================================
    // STEP 0: Harden the process BEFORE any secrets are loaded
    // =========================================================================
    std::cout << "0. Applying process hardening..." << std::endl;
    auto hardening = harden_process();
    print_hardening_status(hardening);
    std::cout << std::endl;

    try {
        // =====================================================================
        // STEP 1: Initialize KeyVault with EK-salted encrypted session
        // =====================================================================
        std::cout << "1. Initializing KeyVault with TPM (EK-salted session)..." << std::endl;
        KeyVault vault(TPM_HANDLE, PUBKEY_PATH, EK_CTX_PATH);
        std::cout << "   OK - TPM key loaded with encrypted session\n" << std::endl;

        // =====================================================================
        // STEP 2: Simulate user uploading encrypted PEM
        // =====================================================================
        std::cout << "2. Simulating user upload..." << std::endl;
        const std::string USER_PASSPHRASE = "UserSecret!456";
        const std::string USER_PEM_PATH = "keys/user_key_A.pem";
        create_test_pem(USER_PEM_PATH, USER_PASSPHRASE);
        std::cout << "   Passphrase: \"" << USER_PASSPHRASE << "\"\n" << std::endl;

        // =====================================================================
        // STEP 3: Protect the passphrase using TPM
        // =====================================================================
        std::cout << "3. Protecting passphrase with TPM public key..." << std::endl;
        ProtectedPassphrase protected_pass = vault.protect("user_key_A", USER_PASSPHRASE);
        print_hex("   Encrypted passphrase", protected_pass.encrypted_data);
        std::cout << std::endl;

        // =====================================================================
        // STEP 4: Serialize for storage (database, file, etc.)
        // =====================================================================
        std::cout << "4. Serializing for database storage..." << std::endl;
        std::vector<uint8_t> db_blob = protected_pass.serialize();
        std::cout << "   Stored " << db_blob.size() << " bytes" << std::endl;
        std::cout << "   (This blob is useless without THIS specific TPM)\n" << std::endl;

        // =====================================================================
        // LATER AT RUNTIME...
        // =====================================================================
        std::cout << "========================================" << std::endl;
        std::cout << "=== Runtime: Using protected key ===" << std::endl;
        std::cout << "========================================\n" << std::endl;

        // Load from "database"
        std::cout << "5. Loading from storage..." << std::endl;
        ProtectedPassphrase loaded = ProtectedPassphrase::deserialize(db_blob);
        std::cout << "   Key ID: " << loaded.key_id << "\n" << std::endl;

        // =====================================================================
        // STEP 6: Sign using protected key
        // =====================================================================
        std::cout << "6. Signing data with protected key..." << std::endl;
        std::cout << "   Timeline:" << std::endl;
        std::cout << "   [1] TPM decrypts passphrase (inside TPM silicon)" << std::endl;
        std::cout << "   [2] Passphrase in SecureBuffer (mlock'd, will be wiped)" << std::endl;
        std::cout << "   [3] OpenSSL loads PEM using passphrase" << std::endl;
        std::cout << "   [4] Passphrase wiped from memory" << std::endl;
        std::cout << "   [5] Sign operation performed" << std::endl;
        std::cout << "   [6] Private key freed (memory wiped)" << std::endl;

        std::string message = "Important document to sign";
        std::vector<uint8_t> data(message.begin(), message.end());

        auto signature = vault.sign_with_protected_key(loaded, USER_PEM_PATH, data);

        std::cout << std::endl;
        if (!signature.empty()) {
            print_hex("   Signature", signature);
            std::cout << "   SUCCESS\n" << std::endl;
        } else {
            std::cout << "   FAILED\n" << std::endl;
        }

        // =====================================================================
        // STEP 7: Decrypt using protected key
        // =====================================================================
        std::cout << "7. Decrypting data with protected key..." << std::endl;
        std::cout << "   (Same pattern as sign - TPM decrypts passphrase first)\n" << std::endl;

        // First, encrypt something with the public key
        std::string secret_message = "Secret data for decryption test";
        std::cout << "   Original: \"" << secret_message << "\"" << std::endl;

        // Load public key from PEM to encrypt
        FILE* pub_fp = fopen(USER_PEM_PATH.c_str(), "r");
        EVP_PKEY* pub_key = PEM_read_PrivateKey(pub_fp, NULL, NULL,
                                                 (void*)USER_PASSPHRASE.c_str());
        fclose(pub_fp);

        // Encrypt with public key
        EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(pub_key, NULL);
        EVP_PKEY_encrypt_init(enc_ctx);
        EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_PADDING);

        size_t enc_len = 0;
        EVP_PKEY_encrypt(enc_ctx, NULL, &enc_len,
                         (const uint8_t*)secret_message.data(), secret_message.size());
        std::vector<uint8_t> encrypted(enc_len);
        EVP_PKEY_encrypt(enc_ctx, encrypted.data(), &enc_len,
                         (const uint8_t*)secret_message.data(), secret_message.size());
        encrypted.resize(enc_len);

        EVP_PKEY_CTX_free(enc_ctx);
        EVP_PKEY_free(pub_key);

        print_hex("   Encrypted", encrypted);

        // Now decrypt using the protected key (TPM decrypts passphrase first)
        auto decrypted = vault.decrypt_with_protected_key(loaded, USER_PEM_PATH, encrypted);

        if (!decrypted.empty()) {
            std::string decrypted_str(decrypted.begin(), decrypted.end());
            std::cout << "   Decrypted: \"" << decrypted_str << "\"" << std::endl;
            std::cout << "   Match: " << (secret_message == decrypted_str ? "YES" : "NO") << std::endl;
            std::cout << "   SUCCESS\n" << std::endl;
        } else {
            std::cout << "   FAILED\n" << std::endl;
        }

        // =====================================================================
        // Summary
        // =====================================================================
        std::cout << "========================================" << std::endl;
        std::cout << "=== Security Summary ===" << std::endl;
        std::cout << "========================================\n" << std::endl;

        std::cout << "Protected against:" << std::endl;
        std::cout << "  [x] Disk cloning (passphrase encrypted by TPM)" << std::endl;
        std::cout << "  [x] Database theft (blob useless without TPM)" << std::endl;
        std::cout << "  [x] Swap file exposure (mlock)" << std::endl;
        std::cout << "  [x] Core dump analysis (PR_SET_DUMPABLE=0)" << std::endl;
        std::cout << "  [x] ptrace from other processes" << std::endl;
        std::cout << "  [x] /proc/<pid>/mem reading (requires CAP_SYS_PTRACE)" << std::endl;
        std::cout << "  [x] Bus sniffing (EK-salted encrypted session)" << std::endl;
        std::cout << std::endl;

        std::cout << "Vulnerable window (unavoidable for user-provided keys):" << std::endl;
        std::cout << "  [ ] Root with CAP_SYS_PTRACE during key operation (~ms)" << std::endl;
        std::cout << "  [ ] Kernel-level memory access" << std::endl;
        std::cout << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "=== Done ===" << std::endl;
    return 0;
}
