#include "../include/hybrid_encryptor.h"
#include <random>
#include <iostream>

// Constructor
HybridCryptoSystem::HybridCryptoSystem() {}

// Generate random AES key
std::string HybridCryptoSystem::generateRandomAESKey(int length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string key;
    std::default_random_engine engine{std::random_device{}()};
    std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);

    for (int i = 0; i < length; i++) {
        key += charset[dist(engine)];
    }
    return key;
}

// Encrypt message
std::pair<std::string, std::string> HybridCryptoSystem::encryptMessage(const std::string& message, const std::string& publicKeyPath) {
    std::string aesKey = generateRandomAESKey(32); // AES-256 key

    // generate hmac
    std::string hmac = generateHMAC(aesKey, message);

    // Encrypt message using AES
    AESEncryptor aes(aesKey);
    std::string encryptedMessage = aes.encrypt(message);
    if (encryptedMessage.empty()) {
        std::cerr << "Encryption failed!" << std::endl;
        return {"", ""};
    }

    // Encrypt AES key using RSA
    RSAEncryption rsa;
    rsa.loadPublicKey(publicKeyPath);
    std::string encryptedAESKey = rsa.encrypt(aesKey);
    if (encryptedAESKey.empty()) {
        std::cerr << "RSA encryption of AES key failed!" << std::endl;
        return {"", ""};
    }

    return {encryptedMessage, encryptedAESKey};
}

// Decrypt message
std::string HybridCryptoSystem::decryptMessage(const std::string& encryptedMessage, const std::string& encryptedAESKey, const std::string& privateKeyPath) {
    RSAEncryption rsa;
    rsa.loadPrivateKey(privateKeyPath);

    std::string decryptedAESKey = rsa.decrypt(encryptedAESKey);
    if (decryptedAESKey.empty()) {
        std::cerr << "Decryption of AES key failed!" << std::endl;
        return "";
    }

    AESEncryptor aes(decryptedAESKey);
    std::string decryptedMessage = aes.decrypt(encryptedMessage);
    if (decryptedMessage.empty()) {
        std::cerr << "Decryption of message failed!" << std::endl;
        return "";
    }
/*
    // Extract the original message and HMAC
    std::string originalMessage = decryptedMessage.substr(0, decryptedMessage.size() - EVP_MAX_MD_SIZE);
    std::string receivedHMAC = decryptedMessage.substr(decryptedMessage.size() - EVP_MAX_MD_SIZE);

    // Recalculate HMAC for verification
    std::string calculatedHMAC = generateHMAC(decryptedAESKey, originalMessage);

    // Verify HMAC
    if (receivedHMAC != calculatedHMAC) {
        std::cerr << "HMAC verification failed! Message integrity compromised." << std::endl;
        return ""; // Return an empty string or handle accordingly
    }
*/
    return decryptedMessage;
}
