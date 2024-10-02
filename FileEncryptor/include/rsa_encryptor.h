#ifndef RSA_ENCRYPTION_H
#define RSA_ENCRYPTION_H

#include <openssl/rsa.h>
#include <string>

class RSAEncryption {
public:
    // Constructor  Destructor
    RSAEncryption(int bits = 2048);
    ~RSAEncryption();

    // pair of keys
    void generateKeys();

    // Save key in file
    void savePrivateKey(const std::string& filename);
    void savePublicKey(const std::string& filename);

    // Load key from file
    void loadPrivateKey(const std::string& filename);
    void loadPublicKey(const std::string& filename);

    // Crypt and decrypt text
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

private:
    RSA* rsa;  // rasa key
    int keyBits;

    // for OpenSSL errors
    void handleErrors();
};

#endif // RSA_ENCRYPTION_H