#ifndef AES_ENCRYPTOR_H
#define AES_ENCRYPTOR_H

#include <string>

class AESEncryptor {
public:
    // constructor with key
    AESEncryptor(std::string key);

    // encrypt function
    std::string encrypt(const std::string &plaintext);

    // decrypt function
    std::string decrypt(const std::string &ciphertext);

private:
    std::string key_;
};

#endif // AES_ENCRYPTOR_H
