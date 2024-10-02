#pragma once

#include <openssl/evp.h>
#include <string>
#include <vector>

class BlowfishEncryptor {
public:
    BlowfishEncryptor();
    ~BlowfishEncryptor();

    void setKey(const std::vector<unsigned char>& key);  // Set encryption key
    void generateKey();  // Generate a random key

    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

    std::vector<unsigned char> getKey() const;

private:
    std::vector<unsigned char> key;  // Blowfish key
    EVP_CIPHER_CTX* ctx;
};