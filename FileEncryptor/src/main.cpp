#include <iostream>
#include <openssl/applink.c>
#include "../include/aes_encryptor.h"
#include "../include/rsa_encryptor.h"
#include "../include/hybrid_encryptor.h"

#include "../include/manage_files.h"
#include "../include/DH_key_exchange.h"
#include "../include/chacha20_encryptor.h"
#include "../include/blowfish_encryptor.h"

#include "../stream/stream_encryption.h"

#include "../ performance_test/random_text.h"
#include "../ performance_test/aes.h"
#include "../ performance_test/blowfish.h"
#include "../ performance_test/rsa.h"
#include "../ performance_test/ecc.h"
#include "../ performance_test/chacha20.h"
#include "../ performance_test/hybrid.h"

using namespace file;

void test_encrypt_decrypt(){
    // Test AES Encryption
    std::string aesKey = "1234567890123456";
    std::string aesPlainText = "Confidential AES message";

    AESEncryptor aes(aesKey);
    std::string aesCipherText = aes.encrypt(aesPlainText);
    std::string aesDecryptedText = aes.decrypt(aesCipherText);

    std::cout << "AES Encrypted: " << aesCipherText << std::endl;
    std::cout << "AES Decrypted: " << aesDecryptedText << std::endl;

    // Test RSA Encryption


    RSAEncryption rsaEncryption;
    rsaEncryption.generateKeys();

    //
    rsaEncryption.savePrivateKey(R"(D:\OOP\CryptoSystem\private_key.pem)");
    rsaEncryption.savePublicKey(R"(D:\OOP\CryptoSystem\public_key.pem)");

    std::cout << "Rsa key saved to file!" << std::endl;


    std::string plaintext = "Confidential RSA message";

    // encrypt
    std::string encryptedMessage = rsaEncryption.encrypt(plaintext);
    std::cout << "Encrypted message: " << encryptedMessage << std::endl;

    // decrypt
    std::string decryptedMessage = rsaEncryption.decrypt(encryptedMessage);
    std::cout << "Decrypted message: " << decryptedMessage << std::endl;
}

void test_hybrid_system(){
    HybridCryptoSystem cryptoSystem;

    // path to RSA keys
    std::string publicKeyPath = R"(D:\OOP\CryptoSystem\public_key.pem)";
    std::string privateKeyPath = R"(D:\OOP\CryptoSystem\private_key.pem)";

    // Generate RSA keys
    RSAEncryption rsa;
    rsa.generateKeys();

    // save keys for future use
    rsa.savePublicKey(publicKeyPath);
    rsa.savePrivateKey(privateKeyPath);


    std::string message = "Secured message using AES-RSA (hybrid_encryption)";

    // encrypt message
    std::pair<std::string, std::string> encryptedData = cryptoSystem.encryptMessage(message, publicKeyPath);
    std::string encryptedMessage = encryptedData.first;
    std::string encryptedAESKey = encryptedData.second;

    std::cout << "Encrypted message: " << encryptedMessage << std::endl;
    std::cout << "AES key encrypted: " << encryptedAESKey << std::endl;

    // Decrypt message
    std::string decryptedMessage = cryptoSystem.decryptMessage(encryptedMessage, encryptedAESKey, privateKeyPath);
    std::cout << "Decrypted message: " << decryptedMessage << std::endl;
}

void showMenu() {
    std::cout << "================= CryptoSystem =================" << std::endl;
    std::cout << "1. Generate RSA Keys" << std::endl;
    std::cout << "2. Encrypt Message (AES)" << std::endl;
    std::cout << "3. Decrypt Message (AES)" << std::endl;
    std::cout << "4. Hybrid Encryption (AES + RSA)" << std::endl;
    std::cout << "5. Hybrid Decryption (AES + RSA)" << std::endl;
    std::cout << "6. HMAC check" << std::endl;
    std::cout << "7. Encrypt Message (ChaCha20)" << std::endl;  // Added
    std::cout << "8. Decrypt Message (ChaCha20)" << std::endl;  // Added
    std::cout << "9. Encrypt Message (Blowfish)" << std::endl;  // Added Blowfish encrypt option
    std::cout << "10. Decrypt Message (Blowfish)" << std::endl;  // Added Blowfish decrypt option
    std::cout << "0. Exit" << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << "Choose an option: ";
}

int main() {

    //test_encrypt_decrypt();
    //test_hybrid_system();
    //exchange();
    //Big_File::test_encrypt_decrypt();

    testAESPerformance(generateRandomMessage(32));
    testBlowfishPerformance(generateRandomMessage(1024*1024)); //1 MB test
    testRSAPerformance(generateRandomMessage(32));
    testECCPerformance(generateRandomMessage(32));
    testChaCha20Performance(generateRandomMessage(1024));
    testHybridPerformance(generateRandomMessage(1024),R"(D:\OOP\CryptoSystem\public_key.pem)",R"(D:\OOP\CryptoSystem\private_key.pem)");

    HybridCryptoSystem cryptoSystem;
    RSAEncryption rsa;
    int option;
    std::string message, encryptedMessage, decryptedMessage, aesKey, hmac, pathToKey, pathToPublicKey, pathToPrivateKey;

    while (true) {
        showMenu();
        std::cin >> option;
        std::cin.ignore();  // // to avoid issues with string input

        switch (option) {
            case 1:
                std::cout << "Enter path to save public key: ";
                std::getline(std::cin, pathToPublicKey);
                std::cout << "Enter path to save private key: ";
                std::getline(std::cin, pathToPrivateKey);

                rsa.generateKeys();
                rsa.savePublicKey(pathToPublicKey);
                rsa.savePrivateKey(pathToPrivateKey);
                std::cout << "RSA keys successfully generated!" << std::endl;
                break;

            case 2:
                std::cout << "Enter message to encrypt (AES): ";
                std::getline(std::cin, message);
             //   aesKey = cryptoSystem.generateRandomAESKey(16);  // generate AES key
                {
                    AESEncryptor aes(aesKey);
                    encryptedMessage = aes.encrypt(message);
                }
                std::cout << "Encrypted message: " << encryptedMessage << std::endl;
                break;

            case 3:
                std::cout << "Enter encrypted message (AES): ";
                std::getline(std::cin, encryptedMessage);
                std::cout << "Enter AES key: ";
                std::getline(std::cin, aesKey);
                {
                    AESEncryptor aes(aesKey);
                    decryptedMessage = aes.decrypt(encryptedMessage);
                }
                std::cout << "Decrypted message: " << decryptedMessage << std::endl;
                break;

            case 4:
                std::cout << "Enter message to encrypt (AES + RSA): ";
                std::getline(std::cin, message);
                std::cout << "Enter path to RSA public key: ";
                std::getline(std::cin, pathToPublicKey);
                {
                    auto [encryptedMessage, encryptedAESKey] = cryptoSystem.encryptMessage(message, pathToPublicKey);
                    std::cout << "Encrypted message: " << encryptedMessage << std::endl;
                    std::cout << "Encrypted AES key: " << encryptedAESKey << std::endl;
                }
                break;

            case 5:
                std::cout << "Enter encrypted message (AES + RSA): ";
                std::getline(std::cin, encryptedMessage);
                std::cout << "Enter encrypted AES key: ";
                std::getline(std::cin, aesKey);
                std::cout << "Enter path to RSA private key: ";
                std::getline(std::cin, pathToPrivateKey);
                decryptedMessage = cryptoSystem.decryptMessage(encryptedMessage, aesKey, pathToPrivateKey);
                std::cout << "Decrypted message: " << decryptedMessage << std::endl;
                break;

            case 6:
                std::cout << "Enter message for HMAC check: ";
                std::getline(std::cin, message);
                std::cout << "Enter secret key for HMAC: ";
                std::getline(std::cin, aesKey);

                hmac = generateHMAC(aesKey, message);
                std::cout << "Generated HMAC: " << hmac << std::endl;
                break;

            case 7: // ChaCha20 Encrypt
                std::cout << "Enter message to encrypt (ChaCha20): ";
                std::getline(std::cin, message);
                {
                    ChaCha20Encryptor chacha20;
                    encryptedMessage = chacha20.encrypt(message);
                    std::cout << "Encrypted message: " << encryptedMessage << std::endl;
                }
                break;

            case 8: // ChaCha20 Decrypt
                std::cout << "Enter message to decrypt (ChaCha20): ";
                std::getline(std::cin, encryptedMessage);
                {
                    ChaCha20Encryptor chacha20;
                    decryptedMessage = chacha20.decrypt(encryptedMessage);
                    std::cout << "Decrypted message: " << decryptedMessage << std::endl;
                }
                break;

            case 9:  // Blowfish Encrypt
                std::cout << "Enter message to encrypt (Blowfish): ";
                std::getline(std::cin, message);
                {
                    BlowfishEncryptor blowfishEncryptor;
                    encryptedMessage =blowfishEncryptor.encrypt(message);
                    std::cout << "Encrypted message: " << encryptedMessage << std::endl;
                }
                break;

            case 10:  // Blowfish Decrypt
                std::cout << "Enter message to decrypt (Blowfish): ";
                std::getline(std::cin, encryptedMessage);
                {
                    BlowfishEncryptor blowfishEncryptor;
                    encryptedMessage = blowfishEncryptor.decrypt(encryptedMessage);
                    std::cout << "Decrypted message: " << decryptedMessage << std::endl;
                }
                break;

            case 0:
                std::cout << "Exiting..." << std::endl;
                return 0;

            default:
                std::cout << "Invalid option. Try again!" << std::endl;
        }
    }
}