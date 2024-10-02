#ifndef CRYPTOSYSTEM_DH_KEY_EXCHANGE_H
#define CRYPTOSYSTEM_DH_KEY_EXCHANGE_H

#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <iostream>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <cstring>

/*
 * DiffieHellman:

    This class handles the generation of the DH parameters and the keys.
    The function generateKeys() generates the private and public keys.
    computeSharedSecret() computes the shared secret using the public key from the other party.

    DH Parameter Generation:
    The prime number p and generator g are generated using DH_generate_parameters_ex().
    This generates a 2048-bit prime and uses DH_GENERATOR_2 as the base (which is a common choice for g)

    Key Exchange:
    Each party computes its own public key and then exchanges it with the other.
    The shared secret is computed using the other party's public key with DH_compute_key().

    Shared Secret:
    After the exchange, both parties derive the same shared secret. This secret can then be used as a key for symmetric encryption (e.g., AES).

    Notes:
    Security Considerations: Diffie-Hellman is vulnerable to man-in-the-middle attacks unless authenticated. To make the protocol secure, it is often used in combination with other cryptographic techniques, such as digital signatures (for authenticity).
    Prime Number Size: In the code, I’ve used a 2048-bit prime, which is considered secure for most purposes. You can adjust this based on your security requirements.

    Practical Use:
    In a real-world system, once Alice and Bob have agreed on a shared secret using Diffie-Hellman,
    they can use it as a key for a symmetric encryption algorithm (e.g., AES) to securely communicate.
 */


class DiffieHellman {
public:
    DiffieHellman() : params(nullptr), pkey(nullptr), peerkey(nullptr), ctx(nullptr) {
        // Generate DH parameters
        params = EVP_PKEY_new();
        EVP_PKEY_CTX *param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
        if (EVP_PKEY_paramgen_init(param_ctx) <= 0) {
            handleErrors();
        }

        // Set DH parameters, generate keypair
        if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(param_ctx, 2048) <= 0) {
            handleErrors();
        }

        if (EVP_PKEY_paramgen(param_ctx, &params) <= 0) {
            handleErrors();
        }

        EVP_PKEY_CTX_free(param_ctx);
    }

    ~DiffieHellman() {
        if (pkey) EVP_PKEY_free(pkey);
        if (peerkey) EVP_PKEY_free(peerkey);
        if (params) EVP_PKEY_free(params);
        if (ctx) EVP_PKEY_CTX_free(ctx);
    }

    // Generate the DH key pair
    void generateKeys() {
        ctx = EVP_PKEY_CTX_new(params, nullptr);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
            handleErrors();
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            handleErrors();
        }
    }

    // Set the peer's public key (received from the other party)
    void setPeerKey(const unsigned char *peer_pub_key, size_t pub_key_len) {
        const unsigned char *p = peer_pub_key;
        peerkey = d2i_PUBKEY(nullptr, &p, pub_key_len);
        if (!peerkey) {
            handleErrors();
        }
    }

    // Compute the shared secret
    std::string computeSharedSecret() {
        unsigned char *secret;
        size_t secret_len;
        EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0) {
            handleErrors();
        }

        if (EVP_PKEY_derive_set_peer(derive_ctx, peerkey) <= 0) {
            handleErrors();
        }

        // Determine buffer length
        if (EVP_PKEY_derive(derive_ctx, nullptr, &secret_len) <= 0) {
            handleErrors();
        }

        secret = (unsigned char*)OPENSSL_malloc(secret_len);
        if (!secret) {
            handleErrors();
        }

        // Perform derivation
        if (EVP_PKEY_derive(derive_ctx, secret, &secret_len) <= 0) {
            handleErrors();
        }

        std::string shared_secret(reinterpret_cast<char*>(secret), secret_len);
        OPENSSL_free(secret);
        EVP_PKEY_CTX_free(derive_ctx);

        return shared_secret;
    }

    // Get the public key in DER format to share with the other party
    std::string getPublicKeyDER() {
        int len = i2d_PUBKEY(pkey, nullptr);
        if (len <= 0) {
            handleErrors();
        }

        unsigned char *pub_key = (unsigned char*)OPENSSL_malloc(len);
        unsigned char *p = pub_key;
        i2d_PUBKEY(pkey, &p);

        std::string pub_key_str(reinterpret_cast<char*>(pub_key), len);
        OPENSSL_free(pub_key);
        return pub_key_str;
    }

private:
    EVP_PKEY *params; // DH parameters
    EVP_PKEY *pkey;   // Local key pair (public/private)
    EVP_PKEY *peerkey; // Peer public key
    EVP_PKEY_CTX *ctx; // Context for generating key pairs

    void handleErrors() {
        ERR_print_errors_fp(stderr);
        abort();
    }
};

void exchange(){
    DiffieHellman alice, bob;

    // Both Alice and Bob generate their DH key pairs
    alice.generateKeys();
    bob.generateKeys();

    // Alice and Bob exchange public keys in DER format
    std::string alicePubKey = alice.getPublicKeyDER();
    std::string bobPubKey = bob.getPublicKeyDER();

    // Alice and Bob set the other's public key
    alice.setPeerKey(reinterpret_cast<const unsigned char*>(bobPubKey.c_str()), bobPubKey.size());
    bob.setPeerKey(reinterpret_cast<const unsigned char*>(alicePubKey.c_str()), alicePubKey.size());

    // Both Alice and Bob compute the shared secret
    std::string aliceSharedSecret = alice.computeSharedSecret();
    std::string bobSharedSecret = bob.computeSharedSecret();

    // Both shared secrets should match
    if (aliceSharedSecret == bobSharedSecret) {
        std::cout << "Shared secret successfully computed!" << std::endl;
    } else {
        std::cout << "Shared secrets do not match!" << std::endl;
    }
}


#endif //CRYPTOSYSTEM_DH_KEY_EXCHANGE_H
