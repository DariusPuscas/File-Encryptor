#pragma once

#include <openssl/hmac.h>
#include <string>

/*
 * Hashed Message Authentication Code
 */

std::string generateHMAC(const std::string& key, const std::string& message);