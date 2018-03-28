#pragma once
#include <stdint.h>
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define AES_BLOCK_SIZE 16
#define AES128_USERKEY_LENGTH 16
#define AES192_USERKEY_LENGTH 24
#define AES256_USERKEY_LENGTH 32

    typedef struct _AES_KEY {
        union {
            uint8_t byte[240];
            uint16_t word[120];
            uint32_t dword[60];
            uint64_t qword[30];
        };
    } AES_KEY;

    //
    //  encrypt
    //
    void accelc_AES128_encrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);
    void accelc_AES192_encrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);
    void accelc_AES256_encrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);

    //
    //  dncrypt
    //
    void accelc_AES128_decrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);
    void accelc_AES192_decrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);
    void accelc_AES256_decrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);

    //
    //  set_key
    //
    void accelc_AES128_set_key(const uint8_t srcUserKey[AES128_USERKEY_LENGTH], AES_KEY* dstKey);
    void accelc_AES192_set_key(const uint8_t srcUserKey[AES192_USERKEY_LENGTH], AES_KEY* dstKey);
    void accelc_AES256_set_key(const uint8_t srcUserKey[AES256_USERKEY_LENGTH], AES_KEY* dstKey);

    //
    //  encrypt_aesni
    //
    void accelc_AES128_encrypt_aesni(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);
    void accelc_AES192_encrypt_aesni(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);
    void accelc_AES256_encrypt_aesni(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);

    //
    //  decrypt_aesni
    //
    void accelc_AES128_decrypt_aesni(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);
    void accelc_AES192_decrypt_aesni(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);
    void accelc_AES256_decrypt_aesni(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey);

    //
    //  decrypt_aesni_fast
    //
    void accelc_AES128_decrypt_aesni_fast(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcInverseKey);
    void accelc_AES192_decrypt_aesni_fast(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcInverseKey);
    void accelc_AES256_decrypt_aesni_fast(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcInverseKey);

    //
    //  set_key_aesni
    //
    void accelc_AES128_set_key_aesni(const uint8_t srcUserKey[AES128_USERKEY_LENGTH], AES_KEY* dstKey);
    void accelc_AES192_set_key_aesni(const uint8_t srcUserKey[AES128_USERKEY_LENGTH], AES_KEY* dstKey);
    void accelc_AES256_set_key_aesni(const uint8_t srcUserKey[AES256_USERKEY_LENGTH], AES_KEY* dstKey);

    //
    //  set_invkey_aesni
    //
    void accelc_AES128_set_invkey_aesni(const AES_KEY* __restrict srcKey, AES_KEY* __restrict dstInverseKey);
    void accelc_AES192_set_invkey_aesni(const AES_KEY* __restrict srcKey, AES_KEY* __restrict dstInverseKey);
    void accelc_AES256_set_invkey_aesni(const AES_KEY* __restrict srcKey, AES_KEY* __restrict dstInverseKey);

#if defined(__cplusplus)
}
#endif

