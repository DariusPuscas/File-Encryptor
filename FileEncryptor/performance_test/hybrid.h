#pragma once

#include <iostream>
#include <chrono>

#include "../include/hybrid_encryptor.h"

void testHybridPerformance(const std::string& message, const std::string& publicKeyPath, const std::string& privateKeyPath) {
    HybridCryptoSystem hybridEncryptor;

    // encrypt
    auto start = std::chrono::high_resolution_clock::now();
    std::pair<std::string, std::string> encryptedData = hybridEncryptor.encryptMessage(message, publicKeyPath);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> encryptionTime = end - start;

    std::cout << "Hybrid Encryption time: " << encryptionTime.count() << " seconds" << std::endl;

    // Decrypt
    start = std::chrono::high_resolution_clock::now();
    std::string decryptedMessage = hybridEncryptor.decryptMessage(encryptedData.first, encryptedData.second, privateKeyPath);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> decryptionTime = end - start;

    std::cout << "Hybrid Decryption time: " << decryptionTime.count() << " seconds" << std::endl;

    // Verify
    if (message == decryptedMessage) {
        std::cout << "Hybrid Encryption Test Passed!" << std::endl;
    } else {
        std::cout << "Hybrid Encryption Test Failed!" << std::endl;
    }
}
