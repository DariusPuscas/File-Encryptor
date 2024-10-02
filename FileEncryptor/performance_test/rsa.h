#pragma once

#include <iostream>
#include <chrono>
#include <vector>
#include "../include/rsa_encryptor.h"

void testRSAPerformance(const std::string& message) {
    RSAEncryption rsaEncryptor(2048);  // Generate 2048 bits key
    rsaEncryptor.generateKeys();

    // encrypt
    auto start = std::chrono::high_resolution_clock::now();
    std::string encrypted = rsaEncryptor.encrypt(message);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> encryptionTime = end - start;
    std::cout << "RSA Encryption time: " << encryptionTime.count() << " seconds" << std::endl;

    // decrypt
    start = std::chrono::high_resolution_clock::now();
    std::string decrypted = rsaEncryptor.decrypt(encrypted);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> decryptionTime = end - start;
    std::cout << "RSA Decryption time: " << decryptionTime.count() << " seconds" << std::endl;

    // Verify
    if (message == decrypted) {
        std::cout << "RSA Test Passed!" << std::endl;
    } else {
        std::cout << "RSA Test Failed!" << std::endl;
    }
}