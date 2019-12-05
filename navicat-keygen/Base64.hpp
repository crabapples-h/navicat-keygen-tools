#pragma once
#include <stdint.h>
#include <vector>
#include <string>

[[nodiscard]]
inline std::string base64_encode(const void* lpBinary, size_t cbBinary) {
    static const std::string::value_type Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static constexpr std::string::value_type PaddingChar = '=';

    std::string szBase64;

    if (auto pbBinary = reinterpret_cast<const uint8_t*>(lpBinary); cbBinary) {
        szBase64.reserve((cbBinary * 8 + 5) / 6);

        uint8_t Idx = 0;
        uint8_t BitsLeft = 8;
        for (size_t i = 0; i < cbBinary;) {
            if (BitsLeft < 6) {
                Idx = pbBinary[i] << (6 - BitsLeft);

                ++i;
                if (i != cbBinary) {
                    Idx |= pbBinary[i] >> (2 + BitsLeft);
                }

                Idx &= 0x3F;
                BitsLeft += 2;
            } else {
                Idx = pbBinary[i] >> (BitsLeft - 6);

                Idx &= 0x3F;
                BitsLeft -= 6;
            }

            szBase64.append(1, Alphabet[Idx]);

            if (BitsLeft == 0) {
                BitsLeft = 8;
                ++i;
            }
        }

        if (szBase64.length() % 4) {
            size_t Padding = 4 - szBase64.length() % 4;
            szBase64.append(Padding, PaddingChar);
        }
    }

    return szBase64;
}

[[nodiscard]]
inline std::string base64_encode(const std::vector<uint8_t>& Binary) {
    return base64_encode(Binary.data(), Binary.size());
}

[[nodiscard]]
inline std::string base64_encode(const std::initializer_list<uint8_t>& Binary) {
    return base64_encode(Binary.begin(), Binary.size());
}

[[nodiscard]]
inline std::vector<uint8_t> base64_decode(std::string_view szBase64) {
    static constexpr std::string::value_type PaddingChar = '=';

    std::vector<uint8_t> Binary;

    if (szBase64.length()) {
        Binary.reserve((szBase64.length() * 6 + 7) / 8);

        uint8_t Byte = 0;
        uint8_t BitsNeed = 8;
        for (size_t i = 0; i < szBase64.length(); ++i) {
            uint8_t Idx;
            if ('A' <= szBase64[i] && szBase64[i] <= 'Z') {
                Idx = szBase64[i] - 'A';
            } else if ('a' <= szBase64[i] && szBase64[i] <= 'z') {
                Idx = szBase64[i] - 'a' + 26;
            } else if ('0' <= szBase64[i] && szBase64[i] <= '9') {
                Idx = szBase64[i] - '0' + 26 + 26;
            } else if (szBase64[i] == '+') {
                Idx = 26 + 26 + 10;
            } else if (szBase64[i] == '/') {
                Idx = 26 + 26 + 10 + 1;
            } else if (szBase64[i] == PaddingChar) {
                for (size_t j = i + 1; j < szBase64.length(); ++j) {
                    if (szBase64[j] != PaddingChar) {
                        throw std::invalid_argument("base64_decode: invalid padding schema.");
                    }
                }

                break;
            } else {
                throw std::invalid_argument("base64_decode: non-Base64 character is detected.");
            }

            if (BitsNeed >= 6) {
                Byte |= Idx;

                BitsNeed -= 6;
                Byte <<= BitsNeed;
            } else {
                Byte |= Idx >> (6 - BitsNeed);
                Binary.push_back(Byte);

                BitsNeed += 2;
                Byte = Idx << BitsNeed;
                if (BitsNeed > 6) {
                    Byte >>= BitsNeed - 6;
                }
            }
        }

        switch (BitsNeed) {
            case 2:
                throw std::invalid_argument("base64_decode: base64 string is corrupted.");
            case 4:
            case 6:
                if (Byte != 0) {
                    throw std::invalid_argument("base64_decode: base64 string is corrupted.");
                }
                break;
            case 0:
            case 8:
                break;
            default:
                __builtin_unreachable();
        }
    }

    return Binary;
}

