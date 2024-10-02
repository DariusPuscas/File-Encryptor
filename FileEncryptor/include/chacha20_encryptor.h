#ifndef CHACHA20ENCRYPTOR_H
#define CHACHA20ENCRYPTOR_H

#include <openssl/evp.h>
#include <string>
#include <vector>

class ChaCha20Encryptor {
public:
    ChaCha20Encryptor();
    ~ChaCha20Encryptor();

    void generateKeyAndNonce();  // Randomly generate key and nonce
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

    void setKey(const std::vector<unsigned char>& key);
    void setNonce(const std::vector<unsigned char>& nonce);

    std::vector<unsigned char> getKey() const;
    std::vector<unsigned char> getNonce() const;

private:
    std::vector<unsigned char> key;
    std::vector<unsigned char> nonce;

    EVP_CIPHER_CTX* ctx;
};

#endif // CHACHA20ENCRYPTOR_H