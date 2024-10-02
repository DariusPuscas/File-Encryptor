#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

namespace Big_File {

    const int AES_BLOCK_SIZE = 16;

// generate AES key and IV (Initial Vector)
   static bool generate_key_iv(unsigned char *key, unsigned char *iv) {
        // Generate random keys (32 bytes for AES-256)
        if (!RAND_bytes(key, 32)) {
            std::cerr << "Error generating key!" << std::endl;
            return false;
        }

        // IV random (16 bytes for AES)
        if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
            std::cerr << "Error generating IV!" << std::endl;
            return false;
        }

        return true;
    }

// encrypt file by reading the contents in chunks
    bool encrypt_file(const std::string &input_file, const std::string &output_file, const unsigned char *key,
                      const unsigned char *iv) {
        std::ifstream ifs(input_file, std::ios::binary);
        std::ofstream ofs(output_file, std::ios::binary);

        if (!ifs.is_open() || !ofs.is_open()) {
            std::cerr << "Error opening the file!" << std::endl;
            return false;
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Error creating context for EVP!" << std::endl;
            return false;
        }

        // Init for AES-256-CBC
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            std::cerr << "Error init AES encryption!" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        const size_t buffer_size = 1024;
        unsigned char buffer_in[buffer_size];
        unsigned char buffer_out[buffer_size + AES_BLOCK_SIZE];

        int out_len;
        while (!ifs.eof()) {
            ifs.read(reinterpret_cast<char *>(buffer_in), buffer_size);
            std::streamsize read_bytes = ifs.gcount();

            if (EVP_EncryptUpdate(ctx, buffer_out, &out_len, buffer_in, read_bytes) != 1) {
                std::cerr << "Encrypt error!" << std::endl;
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }

            ofs.write(reinterpret_cast<char *>(buffer_out), out_len);
        }

        if (EVP_EncryptFinal_ex(ctx, buffer_out, &out_len) != 1) {
            std::cerr << "Encrypt error(final text)!" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        ofs.write(reinterpret_cast<char *>(buffer_out), out_len);

        EVP_CIPHER_CTX_free(ctx);
        ifs.close();
        ofs.close();

        return true;
    }

// decrypt file
    bool decrypt_file(const std::string &input_file, const std::string &output_file, const unsigned char *key,
                      const unsigned char *iv) {
        std::ifstream ifs(input_file, std::ios::binary);
        std::ofstream ofs(output_file, std::ios::binary);

        if (!ifs.is_open() || !ofs.is_open()) {
            std::cerr << "Error opening the file!" << std::endl;
            return false;
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Error creating context for EVP!" << std::endl;
            return false;
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            std::cerr << "Error init AES encryption!" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        const size_t buffer_size = 1024;
        unsigned char buffer_in[buffer_size];
        unsigned char buffer_out[buffer_size + AES_BLOCK_SIZE];

        int out_len;
        while (!ifs.eof()) {
            ifs.read(reinterpret_cast<char *>(buffer_in), buffer_size);
            std::streamsize read_bytes = ifs.gcount();

            if (EVP_DecryptUpdate(ctx, buffer_out, &out_len, buffer_in, read_bytes) != 1) {
                std::cerr << "Error decrypting file!" << std::endl;
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }

            ofs.write(reinterpret_cast<char *>(buffer_out), out_len);
        }

        if (EVP_DecryptFinal_ex(ctx, buffer_out, &out_len) != 1) {
            std::cerr << "Error decrypting file (final text)!" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        ofs.write(reinterpret_cast<char *>(buffer_out), out_len);

        EVP_CIPHER_CTX_free(ctx);
        ifs.close();
        ofs.close();

        return true;
    }

    [[maybe_unused]] int test_encrypt_decrypt() {
        const std::string input_file = R"(D:\OOP\CryptoSystem\stream\input.txt)";
        const std::string encrypted_file = R"(D:\OOP\CryptoSystem\stream\encrypted.bin)";
        const std::string decrypted_file = R"(D:\OOP\CryptoSystem\stream\decrypted.txt)";

        unsigned char key[32]; //  AES-256 key (32 bytes)
        unsigned char iv[AES_BLOCK_SIZE]; // IV for AES

        // Generate key and IV
        if (!generate_key_iv(key, iv)) {
            return 1;
        }

        // encrypt file
        if (!encrypt_file(input_file, encrypted_file, key, iv)) {
            std::cerr << "Error encrypting the file!" << std::endl;
            return 1;
        }
        std::cout << "File encrypted with success!" << std::endl;

        // Decrypt file
        if (!decrypt_file(encrypted_file, decrypted_file, key, iv)) {
            std::cerr << "Error decrypting the file!" << std::endl;
            return 1;
        }
        std::cout << "File decrypted with success!" << std::endl;
        return 0;
    }
}