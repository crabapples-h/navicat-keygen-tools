#include "aes.h"

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

extern const uint32_t accelc_aes_rcon[11];

extern const uint8_t accelc_aes_SBox[256];
extern const uint8_t accelc_aes_InverseSBox[256];

extern const uint8_t accelc_aes_GF2p8_Mul_0x02[256];
extern const uint8_t accelc_aes_GF2p8_Mul_0x03[256];
extern const uint8_t accelc_aes_GF2p8_Mul_0x09[256];
extern const uint8_t accelc_aes_GF2p8_Mul_0x0B[256];
extern const uint8_t accelc_aes_GF2p8_Mul_0x0D[256];
extern const uint8_t accelc_aes_GF2p8_Mul_0x0E[256];

#define Swap(X, Y, Temp)    \
    Temp = X;               \
    X = Y;                  \
    Y = Temp;

void accelc_AES128_encrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey) {

    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[0];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[1];

    uint8_t ShiftTemp = 0;
    for (int i = 1; i < 10; ++i) {

        for (int j = 0; j < 16; ++j)
            srcBytes[j] = accelc_aes_SBox[srcBytes[j]];

        //Shift rows starts;
        //Shift the second row;
        Swap(srcBytes[1], srcBytes[5], ShiftTemp)
        Swap(srcBytes[5], srcBytes[9], ShiftTemp)
        Swap(srcBytes[9], srcBytes[13], ShiftTemp)
        //Shift the third row;
        Swap(srcBytes[2], srcBytes[10], ShiftTemp)
        Swap(srcBytes[6], srcBytes[14], ShiftTemp)
        //Shift the fourth row;
        Swap(srcBytes[3], srcBytes[15], ShiftTemp)
        Swap(srcBytes[15], srcBytes[11], ShiftTemp)
        Swap(srcBytes[11], srcBytes[7], ShiftTemp)
        //Shift rows ends;


        for (int j = 0; j < 16; j += 4) {
            uint8_t temp[4];
            *(uint32_t*)temp = ((uint32_t*)srcBytes)[j / 4];

            srcBytes[j] = (uint8_t)(accelc_aes_GF2p8_Mul_0x02[temp[0]] ^ accelc_aes_GF2p8_Mul_0x03[temp[1]] ^ temp[2] ^ temp[3]);
            srcBytes[j + 1] = (uint8_t)(temp[0] ^ accelc_aes_GF2p8_Mul_0x02[temp[1]] ^ accelc_aes_GF2p8_Mul_0x03[temp[2]] ^ temp[3]);
            srcBytes[j + 2] = (uint8_t)(temp[0] ^ temp[1] ^ accelc_aes_GF2p8_Mul_0x02[temp[2]] ^ accelc_aes_GF2p8_Mul_0x03[temp[3]]);
            srcBytes[j + 3] = (uint8_t)(accelc_aes_GF2p8_Mul_0x03[temp[0]] ^ temp[1] ^ temp[2] ^ accelc_aes_GF2p8_Mul_0x02[temp[3]]);
        }

        ((uint64_t*)(srcBytes))[0] ^= srcKey->qword[i * 2];
        ((uint64_t*)(srcBytes))[1] ^= srcKey->qword[i * 2 + 1];
    }

    for (int j = 0; j < 16; ++j)
        srcBytes[j] = accelc_aes_SBox[srcBytes[j]];

    //Shift rows starts;
    //Shift the second row;
    Swap(srcBytes[1], srcBytes[5], ShiftTemp)
    Swap(srcBytes[5], srcBytes[9], ShiftTemp)
    Swap(srcBytes[9], srcBytes[13], ShiftTemp)
    //Shift the third row;
    Swap(srcBytes[2], srcBytes[10], ShiftTemp)
    Swap(srcBytes[6], srcBytes[14], ShiftTemp)
    //Shift the fourth row;
    Swap(srcBytes[3], srcBytes[15], ShiftTemp)
    Swap(srcBytes[15], srcBytes[11], ShiftTemp)
    Swap(srcBytes[11], srcBytes[7], ShiftTemp)
    //Shift rows ends;

    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[20];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[21];
}

void accelc_AES128_decrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey) {
    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[20];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[21];

    uint8_t ShiftTemp = 0;

    for (int i = 9; i > 0; --i) {
        //Inverse Shift rows starts;
        //Inverse shift the second row;
        Swap(srcBytes[13], srcBytes[9], ShiftTemp)
        Swap(srcBytes[9], srcBytes[5], ShiftTemp)
        Swap(srcBytes[5], srcBytes[1], ShiftTemp)
        //Inverse shift the third row;
        Swap(srcBytes[14], srcBytes[6], ShiftTemp)
        Swap(srcBytes[10], srcBytes[2], ShiftTemp)
        //Inverse shift the fourth row;
        Swap(srcBytes[3], srcBytes[7], ShiftTemp)
        Swap(srcBytes[7], srcBytes[11], ShiftTemp)
        Swap(srcBytes[11], srcBytes[15], ShiftTemp)

        for (int j = 0; j < 16; ++j)
            srcBytes[j] = accelc_aes_InverseSBox[srcBytes[j]];

        ((uint64_t*)srcBytes)[0] ^= srcKey->qword[i * 2];
        ((uint64_t*)srcBytes)[1] ^= srcKey->qword[i * 2 + 1];

        for (int j = 0; j < 16; j += 4) {
            uint8_t temp[4];
            *(uint32_t*)temp = ((uint32_t*)srcBytes)[j / 4];
            srcBytes[j] = (uint8_t)(accelc_aes_GF2p8_Mul_0x0E[temp[0]] ^ accelc_aes_GF2p8_Mul_0x0B[temp[1]] ^ accelc_aes_GF2p8_Mul_0x0D[temp[2]] ^ accelc_aes_GF2p8_Mul_0x09[temp[3]]);
            srcBytes[j + 1] = (uint8_t)(accelc_aes_GF2p8_Mul_0x09[temp[0]] ^ accelc_aes_GF2p8_Mul_0x0E[temp[1]] ^ accelc_aes_GF2p8_Mul_0x0B[temp[2]] ^ accelc_aes_GF2p8_Mul_0x0D[temp[3]]);
            srcBytes[j + 2] = (uint8_t)(accelc_aes_GF2p8_Mul_0x0D[temp[0]] ^ accelc_aes_GF2p8_Mul_0x09[temp[1]] ^ accelc_aes_GF2p8_Mul_0x0E[temp[2]] ^ accelc_aes_GF2p8_Mul_0x0B[temp[3]]);
            srcBytes[j + 3] = (uint8_t)(accelc_aes_GF2p8_Mul_0x0B[temp[0]] ^ accelc_aes_GF2p8_Mul_0x0D[temp[1]] ^ accelc_aes_GF2p8_Mul_0x09[temp[2]] ^ accelc_aes_GF2p8_Mul_0x0E[temp[3]]);
        }
    }

    //Inverse Shift rows starts;
    //Inverse shift the second row;
    Swap(srcBytes[13], srcBytes[9], ShiftTemp)
    Swap(srcBytes[9], srcBytes[5], ShiftTemp)
    Swap(srcBytes[5], srcBytes[1], ShiftTemp)
    //Inverse shift the third row;
    Swap(srcBytes[14], srcBytes[6], ShiftTemp)
    Swap(srcBytes[10], srcBytes[2], ShiftTemp)
    //Inverse shift the fourth row;
    Swap(srcBytes[3], srcBytes[7], ShiftTemp)
    Swap(srcBytes[7], srcBytes[11], ShiftTemp)
    Swap(srcBytes[11], srcBytes[15], ShiftTemp)

    for (int j = 0; j < 16; ++j)
        srcBytes[j] = accelc_aes_InverseSBox[srcBytes[j]];

    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[0];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[1];
}

void accelc_AES128_set_key(const uint8_t srcUserKey[16], AES_KEY* dstKey) {
    dstKey->qword[0] = ((const uint64_t*)srcUserKey)[0];
    dstKey->qword[1] = ((const uint64_t*)srcUserKey)[1];

    for (int i = 4; i < 44; ++i) {
        uint32_t temp = dstKey->dword[i - 1];
        if (i % 4 == 0) {
            temp = _rotr(temp, 8);
            ((uint8_t*)&temp)[0] = accelc_aes_SBox[((uint8_t*)&temp)[0]];
            ((uint8_t*)&temp)[1] = accelc_aes_SBox[((uint8_t*)&temp)[1]];
            ((uint8_t*)&temp)[2] = accelc_aes_SBox[((uint8_t*)&temp)[2]];
            ((uint8_t*)&temp)[3] = accelc_aes_SBox[((uint8_t*)&temp)[3]];
            temp ^= accelc_aes_rcon[i / 4];
        }
        dstKey->dword[i] = dstKey->dword[i - 4] ^ temp;
    }
}



void accelc_AES192_encrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey) {
    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[0];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[1];

    uint8_t ShiftTemp = 0;
    for (int i = 1; i < 12; ++i) {

        for (int j = 0; j < 16; ++j)
            srcBytes[j] = accelc_aes_SBox[srcBytes[j]];

        //Shift rows starts;
        //Shift the second row;
        Swap(srcBytes[1], srcBytes[5], ShiftTemp)
        Swap(srcBytes[5], srcBytes[9], ShiftTemp)
        Swap(srcBytes[9], srcBytes[13], ShiftTemp)
        //Shift the third row;
        Swap(srcBytes[2], srcBytes[10], ShiftTemp)
        Swap(srcBytes[6], srcBytes[14], ShiftTemp)
        //Shift the fourth row;
        Swap(srcBytes[3], srcBytes[15], ShiftTemp)
        Swap(srcBytes[15], srcBytes[11], ShiftTemp)
        Swap(srcBytes[11], srcBytes[7], ShiftTemp)
        //Shift rows ends;

        for (int j = 0; j < 16; j += 4) {
            uint8_t temp[4];
            *(uint32_t*)temp = ((uint32_t*)srcBytes)[j / 4];

            srcBytes[j] = (uint8_t)(accelc_aes_GF2p8_Mul_0x02[temp[0]] ^ accelc_aes_GF2p8_Mul_0x03[temp[1]] ^ temp[2] ^ temp[3]);
            srcBytes[j + 1] = (uint8_t)(temp[0] ^ accelc_aes_GF2p8_Mul_0x02[temp[1]] ^ accelc_aes_GF2p8_Mul_0x03[temp[2]] ^ temp[3]);
            srcBytes[j + 2] = (uint8_t)(temp[0] ^ temp[1] ^ accelc_aes_GF2p8_Mul_0x02[temp[2]] ^ accelc_aes_GF2p8_Mul_0x03[temp[3]]);
            srcBytes[j + 3] = (uint8_t)(accelc_aes_GF2p8_Mul_0x03[temp[0]] ^ temp[1] ^ temp[2] ^ accelc_aes_GF2p8_Mul_0x02[temp[3]]);
        }

        ((uint64_t*)srcBytes)[0] ^= srcKey->qword[i * 2];
        ((uint64_t*)srcBytes)[1] ^= srcKey->qword[i * 2 + 1];
    }

    for (int j = 0; j < 16; ++j)
        srcBytes[j] = accelc_aes_SBox[srcBytes[j]];

    //Shift rows starts;
    //Shift the second row;
    Swap(srcBytes[1], srcBytes[5], ShiftTemp)  //Swap is a MACRO, no need to add ';'.
    Swap(srcBytes[5], srcBytes[9], ShiftTemp)
    Swap(srcBytes[9], srcBytes[13], ShiftTemp)
    //Shift the third row;
    Swap(srcBytes[2], srcBytes[10], ShiftTemp)
    Swap(srcBytes[6], srcBytes[14], ShiftTemp)
    //Shift the fourth row;
    Swap(srcBytes[3], srcBytes[15], ShiftTemp)
    Swap(srcBytes[15], srcBytes[11], ShiftTemp)
    Swap(srcBytes[11], srcBytes[7], ShiftTemp)
    //Shift rows ends;

    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[24];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[25];
}

void accelc_AES192_decrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey) {
    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[24];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[25];

    uint8_t ShiftTemp = 0;

    for (int i = 11; i > 0; --i) {
        //Inverse Shift rows starts;
        //Inverse shift the second row;
        Swap(srcBytes[13], srcBytes[9], ShiftTemp)
        Swap(srcBytes[9], srcBytes[5], ShiftTemp)
        Swap(srcBytes[5], srcBytes[1], ShiftTemp)
        //Inverse shift the third row;
        Swap(srcBytes[14], srcBytes[6], ShiftTemp)
        Swap(srcBytes[10], srcBytes[2], ShiftTemp)
        //Inverse shift the fourth row;
        Swap(srcBytes[3], srcBytes[7], ShiftTemp)
        Swap(srcBytes[7], srcBytes[11], ShiftTemp)
        Swap(srcBytes[11], srcBytes[15], ShiftTemp)

        for (int j = 0; j < 16; ++j)
            srcBytes[j] = accelc_aes_InverseSBox[srcBytes[j]];

        ((uint64_t*)srcBytes)[0] ^= srcKey->qword[i * 2];
        ((uint64_t*)srcBytes)[1] ^= srcKey->qword[i * 2 + 1];

        for (int j = 0; j < 16; j += 4) {
            uint8_t temp[4];
            *(uint32_t*)temp = ((uint32_t*)srcBytes)[j / 4];
            srcBytes[j] = (uint8_t)(accelc_aes_GF2p8_Mul_0x0E[temp[0]] ^ accelc_aes_GF2p8_Mul_0x0B[temp[1]] ^ accelc_aes_GF2p8_Mul_0x0D[temp[2]] ^ accelc_aes_GF2p8_Mul_0x09[temp[3]]);
            srcBytes[j + 1] = (uint8_t)(accelc_aes_GF2p8_Mul_0x09[temp[0]] ^ accelc_aes_GF2p8_Mul_0x0E[temp[1]] ^ accelc_aes_GF2p8_Mul_0x0B[temp[2]] ^ accelc_aes_GF2p8_Mul_0x0D[temp[3]]);
            srcBytes[j + 2] = (uint8_t)(accelc_aes_GF2p8_Mul_0x0D[temp[0]] ^ accelc_aes_GF2p8_Mul_0x09[temp[1]] ^ accelc_aes_GF2p8_Mul_0x0E[temp[2]] ^ accelc_aes_GF2p8_Mul_0x0B[temp[3]]);
            srcBytes[j + 3] = (uint8_t)(accelc_aes_GF2p8_Mul_0x0B[temp[0]] ^ accelc_aes_GF2p8_Mul_0x0D[temp[1]] ^ accelc_aes_GF2p8_Mul_0x09[temp[2]] ^ accelc_aes_GF2p8_Mul_0x0E[temp[3]]);
        }
    }

    //Inverse Shift rows starts;
    //Inverse shift the second row;
    Swap(srcBytes[13], srcBytes[9], ShiftTemp)
    Swap(srcBytes[9], srcBytes[5], ShiftTemp)
    Swap(srcBytes[5], srcBytes[1], ShiftTemp)
    //Inverse shift the third row;
    Swap(srcBytes[14], srcBytes[6], ShiftTemp)
    Swap(srcBytes[10], srcBytes[2], ShiftTemp)
    //Inverse shift the fourth row;
    Swap(srcBytes[3], srcBytes[7], ShiftTemp)
    Swap(srcBytes[7], srcBytes[11], ShiftTemp)
    Swap(srcBytes[11], srcBytes[15], ShiftTemp)

    for (uint8_t j = 0; j < 16; ++j)
        srcBytes[j] = accelc_aes_InverseSBox[srcBytes[j]];

    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[0];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[1];
}

void accelc_AES192_set_key(const uint8_t srcUserKey[24], AES_KEY* dstKey) {
    dstKey->qword[0] = ((const uint64_t*)srcUserKey)[0];
    dstKey->qword[1] = ((const uint64_t*)srcUserKey)[1];
    dstKey->qword[2] = ((const uint64_t*)srcUserKey)[2];

    for (int i = 6; i < 52; ++i) {
        uint32_t temp = dstKey->dword[i - 1];
        if (i % 6 == 0) {
            temp = _rotr(temp, 8);
            ((uint8_t*)&temp)[0] = accelc_aes_SBox[((uint8_t*)&temp)[0]];
            ((uint8_t*)&temp)[1] = accelc_aes_SBox[((uint8_t*)&temp)[1]];
            ((uint8_t*)&temp)[2] = accelc_aes_SBox[((uint8_t*)&temp)[2]];
            ((uint8_t*)&temp)[3] = accelc_aes_SBox[((uint8_t*)&temp)[3]];
            temp ^= accelc_aes_rcon[i / 6];
        }
        dstKey->dword[i] = dstKey->dword[i - 6] ^ temp;
    }
}



void accelc_AES256_encrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey) {
    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[0];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[1];

    uint8_t ShiftTemp = 0;
    for (int i = 1; i < 14; ++i) {

        for (int j = 0; j < 16; ++j)
            srcBytes[j] = accelc_aes_SBox[srcBytes[j]];

        //Shift rows starts;
        //Shift the second row;
        Swap(srcBytes[1], srcBytes[5], ShiftTemp)
        Swap(srcBytes[5], srcBytes[9], ShiftTemp)
        Swap(srcBytes[9], srcBytes[13], ShiftTemp)
        //Shift the third row;
        Swap(srcBytes[2], srcBytes[10], ShiftTemp)
        Swap(srcBytes[6], srcBytes[14], ShiftTemp)
        //Shift the fourth row;
        Swap(srcBytes[3], srcBytes[15], ShiftTemp)
        Swap(srcBytes[15], srcBytes[11], ShiftTemp)
        Swap(srcBytes[11], srcBytes[7], ShiftTemp)
        //Shift rows ends;

        for (int j = 0; j < 16; j += 4) {
            uint8_t temp[4];
            *(uint32_t*)temp = ((uint32_t*)srcBytes)[j / 4];

            srcBytes[j] = (uint8_t)(accelc_aes_GF2p8_Mul_0x02[temp[0]] ^ accelc_aes_GF2p8_Mul_0x03[temp[1]] ^ temp[2] ^ temp[3]);
            srcBytes[j + 1] = (uint8_t)(temp[0] ^ accelc_aes_GF2p8_Mul_0x02[temp[1]] ^ accelc_aes_GF2p8_Mul_0x03[temp[2]] ^ temp[3]);
            srcBytes[j + 2] = (uint8_t)(temp[0] ^ temp[1] ^ accelc_aes_GF2p8_Mul_0x02[temp[2]] ^ accelc_aes_GF2p8_Mul_0x03[temp[3]]);
            srcBytes[j + 3] = (uint8_t)(accelc_aes_GF2p8_Mul_0x03[temp[0]] ^ temp[1] ^ temp[2] ^ accelc_aes_GF2p8_Mul_0x02[temp[3]]);
        }

        ((uint64_t*)srcBytes)[0] ^= srcKey->qword[i * 2];
        ((uint64_t*)srcBytes)[1] ^= srcKey->qword[i * 2 + 1];
    }

    for (int j = 0; j < 16; ++j)
        srcBytes[j] = accelc_aes_SBox[srcBytes[j]];

    //Shift rows starts;
    //Shift the second row;
    Swap(srcBytes[1], srcBytes[5], ShiftTemp)
    Swap(srcBytes[5], srcBytes[9], ShiftTemp)
    Swap(srcBytes[9], srcBytes[13], ShiftTemp)
    //Shift the third row;
    Swap(srcBytes[2], srcBytes[10], ShiftTemp)
    Swap(srcBytes[6], srcBytes[14], ShiftTemp)
    //Shift the fourth row;
    Swap(srcBytes[3], srcBytes[15], ShiftTemp)
    Swap(srcBytes[15], srcBytes[11], ShiftTemp)
    Swap(srcBytes[11], srcBytes[7], ShiftTemp)
    //Shift rows ends;

    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[28];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[29];
}

void accelc_AES256_decrypt(uint8_t srcBytes[AES_BLOCK_SIZE], const AES_KEY* srcKey) {
    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[28];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[29];

    uint8_t ShiftTemp = 0;
    for (int i = 13; i > 0; --i) {
        //Inverse Shift rows starts;
        //Inverse shift the second row;
        Swap(srcBytes[13], srcBytes[9], ShiftTemp)
        Swap(srcBytes[9], srcBytes[5], ShiftTemp)
        Swap(srcBytes[5], srcBytes[1], ShiftTemp)
        //Inverse shift the third row;
        Swap(srcBytes[14], srcBytes[6], ShiftTemp)
        Swap(srcBytes[10], srcBytes[2], ShiftTemp)
        //Inverse shift the fourth row;
        Swap(srcBytes[3], srcBytes[7], ShiftTemp)
        Swap(srcBytes[7], srcBytes[11], ShiftTemp)
        Swap(srcBytes[11], srcBytes[15], ShiftTemp)

        for (int j = 0; j < 16; ++j)
            srcBytes[j] = accelc_aes_InverseSBox[srcBytes[j]];

        ((uint64_t*)srcBytes)[0] ^= srcKey->qword[i * 2];
        ((uint64_t*)srcBytes)[1] ^= srcKey->qword[i * 2 + 1];

        for (int j = 0; j < 16; j += 4) {
            uint8_t temp[4];
            *(uint32_t*)temp = ((uint32_t*)srcBytes)[j / 4];

            srcBytes[j] = (uint8_t)(accelc_aes_GF2p8_Mul_0x0E[temp[0]] ^ accelc_aes_GF2p8_Mul_0x0B[temp[1]] ^ accelc_aes_GF2p8_Mul_0x0D[temp[2]] ^ accelc_aes_GF2p8_Mul_0x09[temp[3]]);
            srcBytes[j + 1] = (uint8_t)(accelc_aes_GF2p8_Mul_0x09[temp[0]] ^ accelc_aes_GF2p8_Mul_0x0E[temp[1]] ^ accelc_aes_GF2p8_Mul_0x0B[temp[2]] ^ accelc_aes_GF2p8_Mul_0x0D[temp[3]]);
            srcBytes[j + 2] = (uint8_t)(accelc_aes_GF2p8_Mul_0x0D[temp[0]] ^ accelc_aes_GF2p8_Mul_0x09[temp[1]] ^ accelc_aes_GF2p8_Mul_0x0E[temp[2]] ^ accelc_aes_GF2p8_Mul_0x0B[temp[3]]);
            srcBytes[j + 3] = (uint8_t)(accelc_aes_GF2p8_Mul_0x0B[temp[0]] ^ accelc_aes_GF2p8_Mul_0x0D[temp[1]] ^ accelc_aes_GF2p8_Mul_0x09[temp[2]] ^ accelc_aes_GF2p8_Mul_0x0E[temp[3]]);
        }
    }

    //Inverse Shift rows starts;
    //Inverse shift the second row;
    Swap(srcBytes[13], srcBytes[9], ShiftTemp)
    Swap(srcBytes[9], srcBytes[5], ShiftTemp)
    Swap(srcBytes[5], srcBytes[1], ShiftTemp)
    //Inverse shift the third row;
    Swap(srcBytes[14], srcBytes[6], ShiftTemp)
    Swap(srcBytes[10], srcBytes[2], ShiftTemp)
    //Inverse shift the fourth row;
    Swap(srcBytes[3], srcBytes[7], ShiftTemp)
    Swap(srcBytes[7], srcBytes[11], ShiftTemp)
    Swap(srcBytes[11], srcBytes[15], ShiftTemp)

    for (int j = 0; j < 16; ++j)
        srcBytes[j] = accelc_aes_InverseSBox[srcBytes[j]];

    ((uint64_t*)srcBytes)[0] ^= srcKey->qword[0];
    ((uint64_t*)srcBytes)[1] ^= srcKey->qword[1];
}

void accelc_AES256_set_key(const uint8_t srcUserKey[32], AES_KEY* dstKey) {
    dstKey->qword[0] = ((const uint64_t*)srcUserKey)[0];
    dstKey->qword[1] = ((const uint64_t*)srcUserKey)[1];
    dstKey->qword[2] = ((const uint64_t*)srcUserKey)[2];
    dstKey->qword[3] = ((const uint64_t*)srcUserKey)[3];

    for (int i = 8; i < 60; ++i) {
        uint32_t temp = dstKey->dword[i - 1];
        if (i % 8 == 0) {
            temp = _rotr(temp, 8);
            ((uint8_t*)&temp)[0] = accelc_aes_SBox[((uint8_t*)&temp)[0]];
            ((uint8_t*)&temp)[1] = accelc_aes_SBox[((uint8_t*)&temp)[1]];
            ((uint8_t*)&temp)[2] = accelc_aes_SBox[((uint8_t*)&temp)[2]];
            ((uint8_t*)&temp)[3] = accelc_aes_SBox[((uint8_t*)&temp)[3]];
            temp ^= accelc_aes_rcon[i / 8];
        }
        if (i % 8 == 4) {
            ((uint8_t*)&temp)[0] = accelc_aes_SBox[((uint8_t*)&temp)[0]];
            ((uint8_t*)&temp)[1] = accelc_aes_SBox[((uint8_t*)&temp)[1]];
            ((uint8_t*)&temp)[2] = accelc_aes_SBox[((uint8_t*)&temp)[2]];
            ((uint8_t*)&temp)[3] = accelc_aes_SBox[((uint8_t*)&temp)[3]];
        }
        dstKey->dword[i] = dstKey->dword[i - 8] ^ temp;
    }
}
