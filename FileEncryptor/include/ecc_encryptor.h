#pragma once

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>

class ECC_encryptor{
public:
    static void handleErrors();
    static void generate_ecc_keypair();

};