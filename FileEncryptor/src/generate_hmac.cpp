#include "../include/generate_hmac.h"

std::string generateHMAC(const std::string& key, const std::string& message) {
    unsigned char *hmacResult;
    unsigned int hmacLength = EVP_MAX_MD_SIZE;
    hmacResult = HMAC(EVP_sha256(), key.c_str(), key.size(),
                      reinterpret_cast<const unsigned char *>(message.c_str()), message.size(),
                      nullptr, &hmacLength);

    return std::string(reinterpret_cast<char *>(hmacResult), hmacLength);
}