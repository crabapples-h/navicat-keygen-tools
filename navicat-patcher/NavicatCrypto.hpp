#pragma once
#include <openssl/crypto.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <string>
#include <stdexcept>

class Navicat11Crypto {
protected:
    using BlockType = uint8_t[BF_BLOCK];

    BF_KEY _BlowfishKey;

    template<bool __UpperCase = true>
    static void _BytesToHex(const void* src, size_t len, char* dst) noexcept {
        auto pb_src = reinterpret_cast<const uint8_t*>(src);
        for (size_t i = 0; i < len; ++i) {
            char h = pb_src[i] >> 4;
            char l = pb_src[i] & 0x0F;

            if constexpr (__UpperCase) {
                h += h >= 10 ? 'A' - 10 : '0';
                l += l >= 10 ? 'A' - 10 : '0';
            } else {
                h += h >= 10 ? 'a' - 10 : '0';
                l += l >= 10 ? 'a' - 10 : '0';
            }

            dst[2 * i] = h;
            dst[2 * i + 1] = l;
        }
    }

    static void _HexToBytes(const char* src, size_t len, void* dst) {
        auto pb_dst = reinterpret_cast<uint8_t*>(dst);
        for (size_t i = 0; i < len; i += 2) {
            uint8_t h = src[i];
            uint8_t l = src[i + 1];

            if ('0' <= h && h <= '9') {
                h -= '0';
            } else if ('A' <= h && h <= 'F') {
                h -= 'A';
            } else if ('a' <= h && h <= 'f') {
                h -= 'a';
            } else {
                throw std::invalid_argument("Non-hex character detected.");
            }

            if ('0' <= l && l <= '9') {
                l -= '0';
            } else if ('A' <= l && l <= 'F') {
                l -= 'A';
            } else if ('a' <= l && l <= 'f') {
                l -= 'a';
            } else {
                throw std::invalid_argument("Non-hex character detected.");
            }

            pb_dst[i / 2] = (h << 4) ^ l;
        }
    }

    static void _XorBlock(BlockType& a, const BlockType& b) noexcept {
        reinterpret_cast<uint64_t&>(a) ^= reinterpret_cast<const uint64_t&>(b);
    }

    [[nodiscard]]
    std::string _EncryptString(const void* lpPlaintext, size_t cbPlaintext) const {
        std::string Ciphertext;

        if (cbPlaintext) {
            Ciphertext.resize(2 * cbPlaintext);

            alignas(sizeof(BlockType)) BlockType CV = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
            alignas(sizeof(BlockType)) BlockType Block;
            auto lpPlaintextBlock = reinterpret_cast<const uint8_t*>(lpPlaintext);
            auto lpCiphertextHexBlock = Ciphertext.data();
            auto BlockCount = cbPlaintext / BF_BLOCK;

            BF_ecb_encrypt(CV, CV, &_BlowfishKey, BF_ENCRYPT);

            for (size_t i = 0; i < BlockCount; ++i, lpPlaintextBlock += sizeof(BlockType), lpCiphertextHexBlock += 2 * sizeof(BlockType)) {
                memcpy(Block, lpPlaintextBlock, sizeof(BlockType));

                _XorBlock(Block, CV);
                BF_ecb_encrypt(Block, Block, &_BlowfishKey, BF_ENCRYPT);
                _XorBlock(CV, Block);

                _BytesToHex(Block, sizeof(Block), lpCiphertextHexBlock);
            }

            auto LeftByteCount = cbPlaintext % sizeof(BlockType);
            if (LeftByteCount) {
                BF_ecb_encrypt(CV, CV, &_BlowfishKey, BF_ENCRYPT);

                for (size_t i = 0; i < LeftByteCount; ++i) {
                    CV[i] ^= lpPlaintextBlock[i];
                }

                _BytesToHex(CV, LeftByteCount, lpCiphertextHexBlock);
            }
        }

        return Ciphertext;
    }

    [[nodiscard]]
    std::string _DecryptString(const char* lpCiphertext, size_t cbCiphertext) const {
        std::string Plaintext;

        if (cbCiphertext) {
            if (cbCiphertext % 2) {
                throw std::invalid_argument("Ciphertext is not a hex string.");
            }

            Plaintext.resize(cbCiphertext / 2);

            alignas(sizeof(BlockType)) BlockType CV = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
            alignas(sizeof(BlockType)) BlockType Block;
            auto lpPlaintextBlock = Plaintext.data();
            auto lpCiphertextHexBlock = lpCiphertext;
            auto BlockCount = cbCiphertext / (2 * sizeof(BlockType));

            BF_ecb_encrypt(CV, CV, &_BlowfishKey, BF_ENCRYPT);

            for (size_t i = 0; i < BlockCount; ++i, lpPlaintextBlock += sizeof(BlockType), lpCiphertextHexBlock += 2 * sizeof(BlockType)) {
                alignas(sizeof(BlockType)) BlockType CiphertextBlock;

                _HexToBytes(lpCiphertextHexBlock, 2 * sizeof(BlockType), CiphertextBlock);
                memcpy(Block, CiphertextBlock, sizeof(BlockType));

                BF_ecb_encrypt(Block, Block, &_BlowfishKey, BF_DECRYPT);
                _XorBlock(Block, CV);
                _XorBlock(CV, CiphertextBlock);

                memcpy(lpPlaintextBlock, Block, sizeof(BlockType));
            }

            auto LeftHexCount = cbCiphertext % (2 * sizeof(BlockType));
            if (LeftHexCount) {
                _HexToBytes(lpCiphertextHexBlock, LeftHexCount, Block);

                BF_ecb_encrypt(CV, CV, &_BlowfishKey, BF_ENCRYPT);

                for (size_t i = 0; i < LeftHexCount / 2; ++i) {
                    lpPlaintextBlock[i] = Block[i] ^ CV[i];
                }
            }
        }

        return Plaintext;
    }

public:

    Navicat11Crypto() noexcept {
        static const uint8_t PresetKey[SHA_DIGEST_LENGTH] = {
            0x42, 0xCE, 0xB2, 0x71, 0xA5, 0xE4, 0x58, 0xB7,
            0x4A, 0xEA, 0x93, 0x94, 0x79, 0x22, 0x35, 0x43,
            0x91, 0x87, 0x33, 0x40
        };

        BF_set_key(&_BlowfishKey, sizeof(PresetKey), PresetKey);
    }

    Navicat11Crypto(const void* lpUserKey, size_t cbUserKey) noexcept {
        SetKey(lpUserKey, cbUserKey);
    }

    Navicat11Crypto(const std::initializer_list<uint8_t>& UserKey) noexcept {
        SetKey(UserKey);
    }

    void SetKey(const void* lpUserKey, size_t cbUserKey) noexcept {
        uint8_t MessageDigest[SHA_DIGEST_LENGTH];

        BF_set_key(
            &_BlowfishKey, 
            sizeof(MessageDigest), 
            SHA1(reinterpret_cast<const uint8_t*>(lpUserKey), cbUserKey, MessageDigest)
        );

        OPENSSL_cleanse(MessageDigest, SHA_DIGEST_LENGTH);
    }

    void SetKey(const std::initializer_list<uint8_t>& UserKey) noexcept {
        uint8_t MessageDigest[SHA_DIGEST_LENGTH];

        BF_set_key(
            &_BlowfishKey,
            sizeof(MessageDigest),
            SHA1(UserKey.begin(), UserKey.size(), MessageDigest)
        );

        OPENSSL_cleanse(MessageDigest, SHA_DIGEST_LENGTH);
    }

    [[nodiscard]]
    std::string EncryptString(const std::string& Plaintext) const {
        return _EncryptString(Plaintext.c_str(), Plaintext.length());
    }

    [[nodiscard]]
    std::string DecryptString(const std::string& Ciphertext) const {
        return _DecryptString(Ciphertext.c_str(), Ciphertext.length());
    }

    void Clear() noexcept {
        OPENSSL_cleanse(&_BlowfishKey, sizeof(_BlowfishKey));
    }

    ~Navicat11Crypto() noexcept {
        Clear();
    }
};

