cmake_minimum_required(VERSION 3.27)
project(CryptoSystem)

set(CMAKE_CXX_STANDARD 23)

set(OPENSSL_ROOT_DIR "C:/vcpkg/installed/x64-windows")
set(OPENSSL_INCLUDE_DIR "C:/vcpkg/installed/x64-windows/include")
set(OPENSSL_CRYPTO_LIBRARY "C:/vcpkg/installed/x64-windows/lib/libcrypto.lib")
set(OPENSSL_SSL_LIBRARY "C:/vcpkg/installed/x64-windows/lib/libssl.lib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive")

find_package(OpenSSL REQUIRED)


add_executable(CryptoSystem src/main.cpp
        include/aes_encryptor.h
        include/rsa_encryptor.h
        src/aes_encryptor.cpp
        src/rsa_encryptor.cpp
        include/hybrid_encryptor.h
        src/hybrid_encryptor.cpp
        include/generate_hmac.h
        src/generate_hmac.cpp
        include/manage_files.h
        include/chacha20_encryptor.h
        src/chacha20_encryptor.cpp
        include/DH_key_exchange.h
        include/blowfish_encryptor.h
        src/blowfish_encryptor.cpp
        include/certificate_manager.h
        include/cloud_save.h
        stream/stream_encryption.h
        include/ecc_encryptor.h
        src/ecc_encryptor.cpp
        " performance_test/aes.h"
        " performance_test/random_text.h"
        " performance_test/blowfish.h"
        " performance_test/rsa.h"
        " performance_test/ecc.h"
        " performance_test/chacha20.h"
        " performance_test/hybrid.h")

target_link_libraries(CryptoSystem PRIVATE OpenSSL::SSL OpenSSL::Crypto)