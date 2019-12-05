#pragma once
#include <stdint.h>
#include <string>
#include <vector>

[[nodiscard]]
inline std::string base32_encode(const void* lpBinary, size_t cbBinary) {
    static const std::string::value_type Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static constexpr std::string::value_type PaddingChar = '=';
    
    std::string szBase32;

    if (auto pbBinary = reinterpret_cast<const uint8_t*>(lpBinary); cbBinary) {
        szBase32.reserve((cbBinary * 8 + 4) / 5);

        uint8_t Idx = 0;
        uint8_t BitsLeft = 8;
        for (size_t i = 0; i < cbBinary;) {
            if (BitsLeft < 5) {
                Idx = pbBinary[i] << (5 - BitsLeft);

                ++i;
                if (i != cbBinary) {
                    Idx |= pbBinary[i] >> (3 + BitsLeft);
                }

                Idx &= 0x1F;
                BitsLeft += 3;
            } else {
                Idx = pbBinary[i] >> (BitsLeft - 5);

                Idx &= 0x1F;
                BitsLeft -= 5;
            }

            szBase32.append(1, Alphabet[Idx]);

            if (BitsLeft == 0) {
                BitsLeft = 8;
                ++i;
            }
        }

        if (szBase32.length() % 8) {
            size_t Padding = 8 - szBase32.length() % 8;
            szBase32.append(Padding, PaddingChar);
        }
    }

    return szBase32;
}

[[nodiscard]]
inline std::string base32_encode(const std::vector<uint8_t>& Binary) {
    return base32_encode(Binary.data(), Binary.size());
}

[[nodiscard]]
inline std::string base32_encode(const std::initializer_list<uint8_t>& Binary) {
    return base32_encode(Binary.begin(), Binary.size());
}

[[nodiscard]]
inline std::vector<uint8_t> base32_decode(std::string_view szBase32) {
    static constexpr std::string::value_type PaddingChar = '=';

    std::vector<uint8_t> Binary;

    if (szBase32.length()) {
        Binary.reserve((szBase32.length() * 5 + 7) / 8);

        uint8_t Byte = 0;
        uint8_t BitsNeed = 8;
        for (size_t i = 0; i < szBase32.length(); ++i) {
            uint8_t Idx;
            if ('A' <= szBase32[i] && szBase32[i] <= 'Z') {
                Idx = szBase32[i] - 'A';
            } else if ('a' <= szBase32[i] && szBase32[i] <= 'z') {
                Idx = szBase32[i] - 'a';
            } else if ('2' <= szBase32[i] && szBase32[i] <= '7') {
                Idx = szBase32[i] - '2' + 26;
            } else if (szBase32[i] == PaddingChar) {
                for (size_t j = i + 1; j < szBase32.length(); ++j) {
                    if (szBase32[j] != PaddingChar) {
                        throw std::invalid_argument("base32_decode: invalid padding schema.");
                    }
                }

                break;
            } else {
                throw std::invalid_argument("base32_decode: non-Base32 character is detected.");
            }

            if (BitsNeed >= 5) {
                Byte |= Idx;

                BitsNeed -= 5;
                Byte <<= BitsNeed;
            } else {
                Byte |= Idx >> (5 - BitsNeed);
                Binary.push_back(Byte);

                BitsNeed += 3;
                Byte = Idx << BitsNeed;
                if (BitsNeed > 5) {
                    Byte >>= BitsNeed - 5;
                }
            }
        }

        switch (BitsNeed) {
            case 1:
            case 2:
            case 3:
                throw std::invalid_argument("base32_decode: base32 string is corrupted.");
            case 4:
            case 5:
            case 6:
            case 7:
                if (Byte != 0) {
                    throw std::invalid_argument("base32_decode: base32 string is corrupted.");
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

