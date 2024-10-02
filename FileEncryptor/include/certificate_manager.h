#pragma once

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include <stdexcept>
#include <iostream>

class X509CertificateManager {
public:
    static void generateKeyPair(const std::string& privateKeyFile, const std::string& publicKeyFile) {
        EVP_PKEY* pkey = nullptr;  // Creăm un pointer EVP_PKEY
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);  // Creăm contextul

        if (!ctx) {
            std::cerr << "Error generating context for EVP_PKEY_CTX" << std::endl;
            return;
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            std::cerr << "Error init key" << std::endl;
            EVP_PKEY_CTX_free(ctx);
            return;
        }

        // set length to 2048 bits
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            std::cerr << "Error setting len" << std::endl;
            EVP_PKEY_CTX_free(ctx);
            return;
        }

        // generate key
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            std::cerr << "Error generating the key" << std::endl;
            EVP_PKEY_CTX_free(ctx);
            return;
        }

        EVP_PKEY_CTX_free(ctx);  // free the context

        // Save private key
        FILE* pkey_file = fopen(privateKeyFile.c_str(), "wb");
        if (!pkey_file) {
            std::cerr << "Error opening the file for private key" << std::endl;
            EVP_PKEY_free(pkey);
            return;
        }
        PEM_write_PrivateKey(pkey_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(pkey_file);

        // save public key
        FILE* pubkey_file = fopen(publicKeyFile.c_str(), "wb");
        if (!pubkey_file) {
            std::cerr << "Error opening the file for public key" << std::endl;
            EVP_PKEY_free(pkey);
            return;
        }
        PEM_write_PUBKEY(pubkey_file, pkey);
        fclose(pubkey_file);

        EVP_PKEY_free(pkey);  // free key

        std::cout << "RSA key generated successfully" << std::endl;
    }
};
