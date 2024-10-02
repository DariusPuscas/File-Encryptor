#include "../include/aes_encryptor.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <cstring>
#include <iostream>
#include <utility>

AESEncryptor::AESEncryptor(std::string key) : key_(std::move(key)) {}

//encrypt
std::string AESEncryptor::encrypt(const std::string &plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();  // create new context
    if (!ctx) {
        std::cerr << "Failed to create context for encryption!" << std::endl;
        return "";
    }

    unsigned char iv[AES_BLOCK_SIZE] = {0};  // Init vector

    // Init AES-256
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char *)key_.c_str(), iv)) {
        std::cerr << "Encryption initialization failed!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::string ciphertext(plaintext.size() + AES_BLOCK_SIZE, '\0');
    int len;
    int ciphertext_len;

    // Crypt data
    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)ciphertext.data(), &len, (unsigned char *)plaintext.c_str(), plaintext.size())) {
        std::cerr << "Encryption failed!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    // Finalise encrypted data
    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)ciphertext.data() + len, &len)) {
        std::cerr << "Final encryption step failed!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);  // clean context

    ciphertext.resize(ciphertext_len);  // Resize the final result
    return ciphertext;
}


std::string AESEncryptor::decrypt(const std::string &ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create context for decryption!" << std::endl;
        return "";
    }

    unsigned char iv[AES_BLOCK_SIZE] = {0};


    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char *)key_.c_str(), iv)) {
        std::cerr << "Decryption initialization failed!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::string plaintext(ciphertext.size(), '\0');
    int len;
    int plaintext_len;


    if (1 != EVP_DecryptUpdate(ctx, (unsigned char *)plaintext.data(), &len, (unsigned char *)ciphertext.c_str(), ciphertext.size())) {
        std::cerr << "Decryption failed!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;


    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext.data() + len, &len)) {
        std::cerr << "Final decryption step failed!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return plaintext;
}
