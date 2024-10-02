#pragma once

#include <iostream>
#include <chrono>
#include <vector>

#include "../include/chacha20_encryptor.h"

void testChaCha20Performance(const std::string& message) {
    ChaCha20Encryptor chacha20Encryptor;
    chacha20Encryptor.generateKeyAndNonce();  // Generate key and random nonce

    // encrypt
    auto start = std::chrono::high_resolution_clock::now();
    std::string encrypted = chacha20Encryptor.encrypt(message);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> encryptionTime = end - start;
    std::cout << "ChaCha20 Encryption time: " << encryptionTime.count() << " seconds" << std::endl;

    // Decrypt
    start = std::chrono::high_resolution_clock::now();
    std::string decrypted = chacha20Encryptor.decrypt(encrypted);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> decryptionTime = end - start;
    std::cout << "ChaCha20 Decryption time: " << decryptionTime.count() << " seconds" << std::endl;

    // Verify
    if (message == decrypted) {
        std::cout << "ChaCha20 Test Passed!" << std::endl;
    } else {
        std::cout << "ChaCha20 Test Failed!" << std::endl;
    }
}