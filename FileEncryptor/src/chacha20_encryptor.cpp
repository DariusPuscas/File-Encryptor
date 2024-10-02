#include "../include/chacha20_encryptor.h"
#include <openssl/rand.h>
#include <iostream>
#include <cstring>

ChaCha20Encryptor::ChaCha20Encryptor() {
    ctx = EVP_CIPHER_CTX_new();
    generateKeyAndNonce();
}

ChaCha20Encryptor::~ChaCha20Encryptor() {
    EVP_CIPHER_CTX_free(ctx);
}

void ChaCha20Encryptor::generateKeyAndNonce() {
    key.resize(32);  // ChaCha20 uses a 256-bit key
    nonce.resize(12);  // ChaCha20 uses a 96-bit nonce

    if (!RAND_bytes(key.data(), key.size())) {
        std::cerr << "Error generating key!" << std::endl;
        exit(1);
    }

    if (!RAND_bytes(nonce.data(), nonce.size())) {
        std::cerr << "Error generating nonce!" << std::endl;
        exit(1);
    }
}

void ChaCha20Encryptor::setKey(const std::vector<unsigned char>& newKey) {
    if (newKey.size() != 32) {
        std::cerr << "Invalid key size for ChaCha20" << std::endl;
        return;
    }
    key = newKey;
}

void ChaCha20Encryptor::setNonce(const std::vector<unsigned char>& newNonce) {
    if (newNonce.size() != 12) {
        std::cerr << "Invalid nonce size for ChaCha20" << std::endl;
        return;
    }
    nonce = newNonce;
}

std::vector<unsigned char> ChaCha20Encryptor::getKey() const {
    return key;
}

std::vector<unsigned char> ChaCha20Encryptor::getNonce() const {
    return nonce;
}

std::string ChaCha20Encryptor::encrypt(const std::string& plaintext) {
    int len;
    int ciphertext_len;
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key.data(), nonce.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

std::string ChaCha20Encryptor::decrypt(const std::string& ciphertext) {
    int len;
    int plaintext_len;
    std::vector<unsigned char> plaintext(ciphertext.size());

    EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key.data(), nonce.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char*)ciphertext.c_str(), ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}
