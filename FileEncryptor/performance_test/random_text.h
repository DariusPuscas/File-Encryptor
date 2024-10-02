#pragma once
#include <string>

// Functie pentru generarea unui mesaj random de o anumita dimensiune
std::string generateRandomMessage(size_t size) {
    std::string message(size, ' ');
    for (size_t i = 0; i < size; ++i) {
        message[i] = 'A' + (rand() % 26);  // caractere random
    }
    return message;
}