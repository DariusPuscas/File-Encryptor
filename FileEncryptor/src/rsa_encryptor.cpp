// rsa_encryption.cpp
#include "../include/rsa_encryptor.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <cstring>

RSAEncryption::RSAEncryption(int bits) : rsa(nullptr), keyBits(bits) {}

RSAEncryption::~RSAEncryption() {
    if (rsa) {
        RSA_free(rsa);
    }
}

void RSAEncryption::handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void RSAEncryption::generateKeys() {
    BIGNUM* bne = BN_new();
    if (BN_set_word(bne, RSA_F4) != 1) {
        handleErrors();
    }

    rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, keyBits, bne, NULL) != 1) {
        handleErrors();
    }

    BN_free(bne);
}

void RSAEncryption::savePrivateKey(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "wb");
    if (!file) {
        handleErrors();
    }
    if (PEM_write_RSAPrivateKey(file, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
        handleErrors();
    }
    fclose(file);
}

void RSAEncryption::savePublicKey(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "wb");
    if (!file) {
        handleErrors();
    }
    if (PEM_write_RSA_PUBKEY(file, rsa) != 1) {
        handleErrors();
    }
    fclose(file);
}

void RSAEncryption::loadPrivateKey(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        handleErrors();
    }
    rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
    if (!rsa) {
        handleErrors();
    }
    fclose(file);
}

void RSAEncryption::loadPublicKey(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        handleErrors();
    }
    rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
    if (!rsa) {
        handleErrors();
    }
    fclose(file);
}

std::string RSAEncryption::encrypt(const std::string& plaintext) {
    unsigned char encrypted[256];
    int encrypted_length = RSA_public_encrypt(plaintext.size(),
                                              (unsigned char*)plaintext.c_str(),
                                              encrypted,
                                              rsa,
                                              RSA_PKCS1_OAEP_PADDING);
    if (encrypted_length == -1) {
        handleErrors();
    }

    return std::string((char*)encrypted, encrypted_length);
}

std::string RSAEncryption::decrypt(const std::string& ciphertext) {
    unsigned char decrypted[256];
    int decrypted_length = RSA_private_decrypt(ciphertext.size(),
                                               (unsigned char*)ciphertext.c_str(),
                                               decrypted,
                                               rsa,
                                               RSA_PKCS1_OAEP_PADDING);
    if (decrypted_length == -1) {
        handleErrors();
    }

    return std::string((char*)decrypted, decrypted_length);
}
