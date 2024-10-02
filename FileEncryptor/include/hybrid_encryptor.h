#ifndef HYBRID_CRYPTOSYSTEM_H
#define HYBRID_CRYPTOSYSTEM_H

#include <string>
#include "aes_encryptor.h"
#include "rsa_encryptor.h"
#include "generate_hmac.h"

class HybridCryptoSystem {
public:
    HybridCryptoSystem();


    std::pair<std::string, std::string> encryptMessage(const std::string& message, const std::string& publicKeyPath);
    std::string decryptMessage(const std::string& encryptedMessage, const std::string& encryptedAESKey, const std::string& privateKeyPath);

private:
    std::string generateRandomAESKey(int length);
};

#endif // HYBRID_CRYPTOSYSTEM_H
