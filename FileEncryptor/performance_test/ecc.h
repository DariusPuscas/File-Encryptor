#pragma once

#include <iostream>
#include <chrono>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "../include/ecc_encryptor.h"
#include "../ performance_test/random_text.h"

void testECCPerformance(const std::string& message) {
    ECC_encryptor eccEncryptor;

    // Generate ecc pair
    auto start = std::chrono::high_resolution_clock::now();
    eccEncryptor.generate_ecc_keypair();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> keygenTime = end - start;
    std::cout << "ECC Key Generation time: " << keygenTime.count() << " seconds" << std::endl;


}