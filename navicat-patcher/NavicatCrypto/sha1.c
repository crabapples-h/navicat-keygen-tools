#include "sha1.h"
#include <memory.h>

#if defined(_MSC_VER)
#include <intrin.h>
#define _bswap _byteswap_ulong
#define _bswap64 _byteswap_uint64
#elif defined(__GNUC__)
#include <x86intrin.h>
#endif

#define SHA1_BLOCKSIZE 64

void accelc_SHA1_init(SHA1_BUFFER* HashBuffer) {
    HashBuffer->dword[0] = 0x67452301;
    HashBuffer->dword[1] = 0xEFCDAB89;
    HashBuffer->dword[2] = 0x98BADCFE;
    HashBuffer->dword[3] = 0x10325476;
    HashBuffer->dword[4] = 0xC3D2E1F0;
}

void accelc_SHA1_update(const void* __restrict srcBytes, size_t srcBytesLength, 
                        SHA1_BUFFER* __restrict HashBuffer) {
    uint32_t Buffer[80] = { 0 };
    uint32_t a, b, c, d, e;
    const uint32_t (*MessageBlock)[16] = srcBytes;

    size_t RoundsOfMainCycle = srcBytesLength / SHA1_BLOCKSIZE;
    for (size_t i = 0; i < RoundsOfMainCycle; ++i) {

        for (int j = 0; j < 16; ++j)
            Buffer[j] = _bswap(MessageBlock[i][j]);

        for (int j = 16; j < 80; ++j) {
            uint32_t temp = Buffer[j - 3] ^ Buffer[j - 8] ^ Buffer[j - 14] ^ Buffer[j - 16];
            Buffer[j] = _rotl(temp, 1);
        }
        a = HashBuffer->dword[0];
        b = HashBuffer->dword[1];
        c = HashBuffer->dword[2];
        d = HashBuffer->dword[3];
        e = HashBuffer->dword[4];

        for (int j = 0; j < 20; ++j) {
            uint32_t T = _rotl(a, 5);
            T += ((b & c) ^ (~b & d)) + e + 0x5A827999 + Buffer[j];
            e = d;
            d = c;
            c = _rotl(b, 30);
            b = a;
            a = T;
        }
        for (int j = 20; j < 40; ++j) {
            uint32_t T = _rotl(a, 5);
            T += (b ^ c ^ d) + e + 0x6ED9EBA1 + Buffer[j];
            e = d;
            d = c;
            c = _rotl(b, 30);
            b = a;
            a = T;
        }
        for (int j = 40; j < 60; ++j) {
            uint32_t T = _rotl(a, 5);
            T += ((b & c) ^ (b & d) ^ (c & d)) + e + 0x8F1BBCDC + Buffer[j];
            e = d;
            d = c;
            c = _rotl(b, 30);
            b = a;
            a = T;
        }
        for (int j = 60; j < 80; ++j) {
            uint32_t T = _rotl(a, 5);
            T += (b ^ c ^ d) + e + 0xCA62C1D6 + Buffer[j];
            e = d;
            d = c;
            c = _rotl(b, 30);
            b = a;
            a = T;
        }
        HashBuffer->dword[0] += a;
        HashBuffer->dword[1] += b;
        HashBuffer->dword[2] += c;
        HashBuffer->dword[3] += d;
        HashBuffer->dword[4] += e;
    }
}

void accelc_SHA1_final(const void* __restrict LeftBytes, size_t LeftBytesLength, uint64_t TotalBytesLength,
                       const SHA1_BUFFER* HashBuffer, SHA1_DIGEST* Hash) {
    if (HashBuffer != Hash)
        memcpy(Hash, HashBuffer, sizeof(SHA1_BUFFER));

    if (LeftBytesLength >= SHA1_BLOCKSIZE) {
        accelc_SHA1_update(LeftBytes, LeftBytesLength, Hash);
        LeftBytes = (const uint8_t*)LeftBytes + (LeftBytesLength / SHA1_BLOCKSIZE) * SHA1_BLOCKSIZE;
        LeftBytesLength %= SHA1_BLOCKSIZE;
    }

    uint8_t Extra[128] = { 0 };
    for (size_t i = 0; i < LeftBytesLength; ++i)
        Extra[i] = ((const uint8_t*)LeftBytes)[i];

    Extra[LeftBytesLength] = 0x80;
    *(uint64_t*)(Extra + (LeftBytesLength >= 64 - 8 ? 128 - 8 : 64 - 8)) = _bswap64(TotalBytesLength * 8);

    accelc_SHA1_update(Extra, LeftBytesLength >= 56 ? 128 : 64, Hash);

    Hash->dword[0] = _bswap(Hash->dword[0]);
    Hash->dword[1] = _bswap(Hash->dword[1]);
    Hash->dword[2] = _bswap(Hash->dword[2]);
    Hash->dword[3] = _bswap(Hash->dword[3]);
    Hash->dword[4] = _bswap(Hash->dword[4]);
}

void accelc_SHA1(const void* __restrict srcBytes, size_t srclen,
                 SHA1_DIGEST* __restrict Hash) {
    accelc_SHA1_init(Hash);
    accelc_SHA1_update(srcBytes, srclen, Hash);
    accelc_SHA1_final((uint8_t*)srcBytes + (srclen / SHA1_BLOCKSIZE) * SHA1_BLOCKSIZE, srclen % SHA1_BLOCKSIZE, srclen, Hash, Hash);
}