#pragma once
#include <openssl/crypto.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>

#include <string>

#ifdef _DEBUG
#pragma comment(lib, "libcryptoMTd.lib")
#else
#pragma comment(lib, "libcryptoMT.lib")
#endif
#pragma comment(lib, "WS2_32.lib")      // some symbol are used in OpenSSL static lib
#pragma comment(lib, "Crypt32.lib")     // some symbol are used in OpenSSL static lib

class Navicat11Crypto {
protected:
    BF_KEY BlowfishKey;

    void BytesToHex(const void* src, size_t len, char* dst) {
        for (size_t i = 0; i < len; ++i) {
            char h = reinterpret_cast<const uint8_t*>(src)[i] >> 4;
            char l = reinterpret_cast<const uint8_t*>(src)[i] & 0x0F;

            h += h >= 10 ? 'A' - 10 : '0';
            l += l >= 10 ? 'A' - 10 : '0';
            dst[2 * i] = h;
            dst[2 * i + 1] = l;
        }
    }

    bool CheckHex(const char* src, size_t len) {
        if (len % 2 != 0)
            return false;

        for (size_t i = 0; i < len; i += 2) {
            char h = src[i];
            char l = src[i + 1];

            if (src[i] < '0' || src[i] > 'F')
                return false;
            if (src[i] < 'A' && src[i] > '9')
                return false;
            if (src[i + 1] < '0' || src[i + 1] > 'F')
                return false;
            if (src[i + 1] < 'A' && src[i + 1] > '9')
                return false;
        }

        return true;
    }

    void HexToBytes(const char* src, size_t len, void* dst) {
        for (size_t i = 0; i < len; i += 2) {
            uint8_t h = src[i];
            uint8_t l = src[i + 1];

            h -= h > '9' ? 'A' - 10 : '0';
            l -= l > '9' ? 'A' - 10 : '0';

            reinterpret_cast<uint8_t*>(dst)[i / 2] = (h << 4) ^ l;
        }
    }

public:

    Navicat11Crypto() {
        static const uint8_t PresetKey[20] = {
            0x42, 0xCE, 0xB2, 0x71, 0xA5, 0xE4, 0x58, 0xB7,
            0x4A, 0xEA, 0x93, 0x94, 0x79, 0x22, 0x35, 0x43,
            0x91, 0x87, 0x33, 0x40
        };

        BF_set_key(&BlowfishKey, SHA_DIGEST_LENGTH, PresetKey);
    }

    Navicat11Crypto(const void* UserKey, size_t Length) {
        SetKey(UserKey, Length);
    }

    void SetKey(const void* UserKey, size_t Length) {
        unsigned char MessageDigest[SHA_DIGEST_LENGTH];

        SHA1(reinterpret_cast<const unsigned char*>(UserKey), Length, MessageDigest);
        BF_set_key(&BlowfishKey, SHA_DIGEST_LENGTH, MessageDigest);
        OPENSSL_cleanse(MessageDigest, SHA_DIGEST_LENGTH);
    }

    std::string EncryptString(const void* srcBytes, size_t srclen) {
        std::string ret;
        uint8_t CV[BF_BLOCK] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        };

        if (srclen == 0)
            return ret;
        
        ret.resize(2 * srclen);

        BF_ecb_encrypt(CV, CV, &BlowfishKey, BF_ENCRYPT);

        const uint64_t* blocks = reinterpret_cast<const uint64_t*>(srcBytes);
        size_t blocks_len = srclen / BF_BLOCK;
        for (size_t i = 0; i < blocks_len; ++i) {
            union {
                uint8_t byte[8];
                uint64_t qword;
            } temp;

            temp.qword = blocks[i];
            temp.qword ^= *reinterpret_cast<uint64_t*>(CV);
            BF_ecb_encrypt(temp.byte, temp.byte, &BlowfishKey, BF_ENCRYPT);
            *reinterpret_cast<uint64_t*>(CV) ^= temp.qword;
            BytesToHex(&temp, 8, ret.data() + 16 * i);
        }

        if (srclen % BF_BLOCK) {
            BF_ecb_encrypt(CV, CV, &BlowfishKey, BF_ENCRYPT);
            for (size_t i = 0; i < srclen % BF_BLOCK; ++i) {
                CV[i] ^= reinterpret_cast<const uint8_t*>(blocks + blocks_len)[i];
            }
            BytesToHex(CV, srclen % BF_BLOCK, ret.data() + 16 * blocks_len);
        }

        return ret;
    }

    std::string DecryptString(const char* srchex, size_t srclen) {
        std::string ret;
        uint8_t CV[BF_BLOCK] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        };

        if (CheckHex(srchex, srclen) == false)
            return ret;

        ret.resize(srclen / 2);
        
        BF_ecb_encrypt(CV, CV, &BlowfishKey, BF_ENCRYPT);

        const char(*blocks)[16] = reinterpret_cast<const char(*)[16]>(srchex);
        size_t blocks_len = srclen / 16;
        for (size_t i = 0; i < blocks_len; ++i) {
            union {
                uint8_t byte[8];
                uint64_t qword;
            } temp, temp2;

            HexToBytes(blocks[i], 16, temp.byte);
            temp2.qword = temp.qword;
            BF_ecb_encrypt(temp.byte, temp.byte, &BlowfishKey, BF_DECRYPT);
            temp.qword ^= *reinterpret_cast<uint64_t*>(CV);
            *reinterpret_cast<uint64_t*>(ret.data() + 8 * i) = temp.qword;
            *reinterpret_cast<uint64_t*>(CV) ^= temp2.qword;
        }

        if (srclen % 16) {
            union {
                uint8_t byte[8];
                uint64_t qword;
            } temp = { };
            HexToBytes(blocks[blocks_len], srclen % 16, temp.byte);

            BF_ecb_encrypt(CV, CV, &BlowfishKey, BF_ENCRYPT);
            for (size_t i = 0; i < (srclen % 16) / 2; ++i)
                ret[blocks_len * 8 + i] = temp.byte[i] ^ CV[i];
        }

        return ret;
    }

    void Clear() {
        OPENSSL_cleanse(&BlowfishKey, sizeof(BlowfishKey));
    }

    ~Navicat11Crypto() {
        Clear();
    }

};
