#include "../include/blowfish_encryptor.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <cstring>

BlowfishEncryptor::BlowfishEncryptor() {
    ctx = EVP_CIPHER_CTX_new();
    generateKey();  // Generate a default key at the initialization
}

BlowfishEncryptor::~BlowfishEncryptor() {
    EVP_CIPHER_CTX_free(ctx);
}

void BlowfishEncryptor::generateKey() {
    key.resize(16);  // Blowfish key size can vary, we'll use 128-bit (16 bytes)
    if (!RAND_bytes(key.data(), key.size())) {
        std::cerr << "Error generating Blowfish key!" << std::endl;
        exit(1);
    }
}

void BlowfishEncryptor::setKey(const std::vector<unsigned char>& newKey) {
    if (newKey.size() < 4 || newKey.size() > 56) {  // Blowfish allows 32 to 448 bits (4-56 bytes)
        std::cerr << "Invalid Blowfish key size!" << std::endl;
        return;
    }
    key = newKey;
}

std::vector<unsigned char> BlowfishEncryptor::getKey() const {
    return key;
}

std::string BlowfishEncryptor::encrypt(const std::string& plaintext) {
    int len;
    int ciphertext_len;
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    // Initialize encryption
    EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, key.data(), NULL);  // Using CBC mode without an IV (Initialization Vector) for simplicity

    // Encrypt the data
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len = len;

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

std::string BlowfishEncryptor::decrypt(const std::string& ciphertext) {
    int len;
    int plaintext_len;
    std::vector<unsigned char> plaintext(ciphertext.size());

    // Initialize decryption
    EVP_DecryptInit_ex(ctx, EVP_bf_cbc(), NULL, key.data(), NULL);

    // Decrypt the data
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char*)ciphertext.c_str(), ciphertext.size());
    plaintext_len = len;

    // Finalize decryption
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}
