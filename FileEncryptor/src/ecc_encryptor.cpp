#include "../include/ecc_encryptor.h"

void ECC_encryptor::handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void ECC_encryptor::generate_ecc_keypair() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pctx = nullptr;

   // init context
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) handleErrors();

    // Set type of ECC curves , using P-256 curve (prime256v1)
    if (EVP_PKEY_paramgen_init(pctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) handleErrors();

    EVP_PKEY* params = nullptr;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0) handleErrors();
    EVP_PKEY_CTX_free(pctx); // clean context

    //create context to generate private key
    pctx = EVP_PKEY_CTX_new(params, nullptr);
    if (!pctx) handleErrors();

    // Generate key pair (public/private)
    if (EVP_PKEY_keygen_init(pctx) <= 0) handleErrors();
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) handleErrors();

    // Save private key in a PEM file
    FILE* priv_key_file = fopen("ecc_private_key.pem", "w");
    if (!PEM_write_PrivateKey(priv_key_file, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        handleErrors();
    }
    fclose(priv_key_file);

    // Save public key in a PEM file
    FILE* pub_key_file = fopen("ecc_pub_key.pem", "w");
    if (!PEM_write_PUBKEY(pub_key_file, pkey)) {
        handleErrors();
    }
    fclose(pub_key_file);

    // clean
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);

    std::cout << "Keys generated with success!" << std::endl;
}
