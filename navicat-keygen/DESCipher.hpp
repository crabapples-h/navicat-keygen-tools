#pragma once
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <memory.h>

class DESCipher {
private:
    DES_cblock _Key;
    DES_key_schedule _Schedule;
public:

    DESCipher() noexcept : _Key{}, _Schedule{} {}

    void SetKey(const void* pKey) noexcept {
        memcpy(&_Key, pKey, sizeof(_Key));
        DES_set_odd_parity(&_Key);
        DES_set_key(&_Key, &_Schedule);
    }

    void Clear() noexcept {
        OPENSSL_cleanse(&_Key, sizeof(_Key));
        OPENSSL_cleanse(&_Schedule, sizeof(_Schedule));
    }

    void EncryptBlock(void* pBuffer) noexcept {
        DES_cblock block;
        DES_ecb_encrypt(reinterpret_cast<const_DES_cblock*>(pBuffer), &block, &_Schedule, DES_ENCRYPT);
        memcpy(pBuffer, &block, sizeof(block));
    }

    void DecryptBlock(void* pBuffer) noexcept {
        DES_cblock block;
        DES_ecb_encrypt(reinterpret_cast<const_DES_cblock*>(pBuffer), &block, &_Schedule, DES_DECRYPT);
        memcpy(pBuffer, &block, sizeof(block));
    }

    ~DESCipher() noexcept {
        Clear();
    }
};

