#pragma once

#include <iostream>
#include <chrono>
#include <vector>
#include "../include/aes_encryptor.h"

// test AES
void testAESPerformance(const std::string& message) {
    AESEncryptor aesEncryptor("ThisIsA32ByteKey1234567890ABCDEF"); // 32 bytes key

    // encrypt
    auto start = std::chrono::high_resolution_clock::now();
    std::string encrypted = aesEncryptor.encrypt(message);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> encryptionTime = end - start;
    std::cout << "AES Encryption time: " << encryptionTime.count() << " seconds" << std::endl;

    // decrypt
    start = std::chrono::high_resolution_clock::now();
    std::string decrypted = aesEncryptor.decrypt(encrypted);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> decryptionTime = end - start;
    std::cout << "AES Decryption time: " << decryptionTime.count() << " seconds" << std::endl;

    // Verify
    if (message == decrypted) {
        std::cout << "AES Test Passed!" << std::endl;
    } else {
        std::cout << "AES Test Failed!" << std::endl;
    }
}
