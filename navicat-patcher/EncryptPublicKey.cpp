// to avoid "AES_KEY" definaition conflict
#include "NavicatCrypto/NavicatCrypto.hpp"

namespace patcher {

    static Navicat11Crypto cipher("23970790", 8);

    std::string EncryptPublicKey(const char* public_key, size_t len) {
        auto&& temp = cipher.EncryptString(public_key, len);
        return std::string(temp.begin(), temp.end());
    }

}