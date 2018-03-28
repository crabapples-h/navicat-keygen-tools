#pragma once
#include <stdint.h>
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

    typedef struct _SHA1_DIGEST {
        union {
            uint8_t byte[20];
            uint32_t dword[5];
        };
    } SHA1_DIGEST, SHA1_BUFFER;
    
    void accelc_SHA1_init(SHA1_BUFFER* HashBuffer);

    void accelc_SHA1_update(const void* __restrict srcBytes, size_t srcBytesLength, 
                            SHA1_BUFFER* __restrict HashBuffer);

    void accelc_SHA1_final(const void* __restrict LeftBytes, size_t LeftBytesLength, uint64_t TotalBytesLength,
                           const SHA1_BUFFER* HashBuffer, SHA1_DIGEST* Hash);

    void accelc_SHA1(const void* __restrict srcBytes, size_t srclen,
                     SHA1_DIGEST* __restrict Hash);

#if defined(__cplusplus)
}
#endif