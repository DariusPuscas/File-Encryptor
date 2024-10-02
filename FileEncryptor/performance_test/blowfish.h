#pragma once

#include <string>
#include <iostream>
#include <chrono>
#include <vector>
#include "../include/blowfish_encryptor.h"

void testBlowfishPerformance(const std::string& message) {
    BlowfishEncryptor blowfishEncryptor;
    blowfishEncryptor.generateKey();  // generate blowfish key

    // encrypt
    auto start = std::chrono::high_resolution_clock::now();
    std::string encrypted = blowfishEncryptor.encrypt(message);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> encryptionTime = end - start;
    std::cout << "Blowfish Encryption time: " << encryptionTime.count() << " seconds" << std::endl;

    // decrypt
    start = std::chrono::high_resolution_clock::now();
    std::string decrypted = blowfishEncryptor.decrypt(encrypted);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> decryptionTime = end - start;
    std::cout << "Blowfish Decryption time: " << decryptionTime.count() << " seconds" << std::endl;

    // Verify
    if (message == decrypted) {
        std::cout << "Blowfish Test Passed!" << std::endl;
    } else {
        std::cout << "Blowfish Test Failed!" << std::endl;
    }
}