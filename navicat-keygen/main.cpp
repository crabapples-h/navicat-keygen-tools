#include <stdio.h>
#include <memory.h>
#include <iostream>
#include <string>
#include <chrono>

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/des.h>
#include <openssl/evp.h>

void GenerateSnKey(char(&SnKey)[16]) {
    static char EncodeTable[] = "ABCDEFGH8JKLMN9PQRSTUVWXYZ234567"; // Thanks for discoveries from @Wizr.
                                                                    // This is not a standard Base32 alphabet table.
                                                                    // The differences are:
                                                                    // |  Standard  |  Non-standard  |
                                                                    // |------------|----------------|
                                                                    // |    'I'     |      '8'       |
                                                                    // |    'O'     |      '9'       |
    
    static DES_cblock DESKey = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };

    unsigned char temp_snKey[10] = { 0x68, 0x2a };   //  must start with 0x68, 0x2a
    temp_snKey[2] = rand();
    temp_snKey[3] = rand();
    temp_snKey[4] = rand();
#if defined(NAVICAT_12_ENG)
    temp_snKey[5] = 0xAC;       // Must be 0xAC for English version.
    temp_snKey[6] = 0x88;       // Must be 0x88 for English version.
#elif defined(NAVICAT_12_CHS)
    temp_snKey[5] = 0xCE;       // Must be 0xCE for Simplified Chinese version.
    temp_snKey[6] = 0x32;       // Must be 0x32 for Simplified Chinese version.
#elif defined(NAVICAT_12_CHT)
    temp_snKey[5] = 0xAA;       // Must be 0xAA for Traditional Chinese version.
    temp_snKey[6] = 0x99;       // Must be 0x99 for Traditional Chinese version.
#else
#error "Navicat version is not specified."
#endif
    temp_snKey[7] = 0x65;       // 0x65 - commercial, 0x66 - non-commercial
    temp_snKey[8] = 0xC0;       // High 4-bits = version number. Low 4-bits doesn't know, but can be used to delay activation time.
    temp_snKey[9] = 0x32;       // 0xFB is Not-For-Resale-30-days license.
                                // 0xFC is Not-For-Resale-90-days license.
                                // 0xFD is Not-For-Resale-365-days license.
                                // 0xFE is Not-For-Resale license.
                                // 0xFF is Site license.
                                // Must not be 0x00. 0x01-0xFA is ok.

    DES_key_schedule schedule;
    DES_set_odd_parity(&DESKey);
    DES_set_key(&DESKey, &schedule);
    DES_cblock enc_temp_snKey;

    DES_ecb_encrypt(reinterpret_cast<const_DES_cblock*>(temp_snKey + 2), &enc_temp_snKey, &schedule, DES_ENCRYPT);
    memmove(temp_snKey + 2, enc_temp_snKey, sizeof(enc_temp_snKey));

    SnKey[0] = EncodeTable[temp_snKey[0] >> 3];
    SnKey[1] = EncodeTable[(temp_snKey[0] & 0x07) << 2 | temp_snKey[1] >> 6];
    SnKey[2] = EncodeTable[temp_snKey[1] >> 1 & 0x1F];
    SnKey[3] = EncodeTable[(temp_snKey[1] & 0x1) << 4 | temp_snKey[2] >> 4];
    SnKey[4] = EncodeTable[(temp_snKey[2] & 0xF) << 1 | temp_snKey[3] >> 7];
    SnKey[5] = EncodeTable[temp_snKey[3] >> 2 & 0x1F];
    SnKey[6] = EncodeTable[temp_snKey[3] << 3 & 0x1F | temp_snKey[4] >> 5];
    SnKey[7] = EncodeTable[temp_snKey[4] & 0x1F];

    SnKey[8] = EncodeTable[temp_snKey[5] >> 3];
    SnKey[9] = EncodeTable[(temp_snKey[5] & 0x07) << 2 | temp_snKey[6] >> 6];
    SnKey[10] = EncodeTable[temp_snKey[6] >> 1 & 0x1F];
    SnKey[11] = EncodeTable[(temp_snKey[6] & 0x1) << 4 | temp_snKey[7] >> 4];
    SnKey[12] = EncodeTable[(temp_snKey[7] & 0xF) << 1 | temp_snKey[8] >> 7];
    SnKey[13] = EncodeTable[temp_snKey[8] >> 2 & 0x1F];
    SnKey[14] = EncodeTable[temp_snKey[8] << 3 & 0x1F | temp_snKey[9] >> 5];
    SnKey[15] = EncodeTable[temp_snKey[9] & 0x1F];

    printf("\r\n");
    printf("SnKey:\r\n");
    printf("%.4s-%.4s-%.4s-%.4s\r\n", SnKey, SnKey + 4, SnKey + 8, SnKey + 12);
    printf("\r\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage:\n");
        printf("    ./navicat-keygen <RSA-2048 PrivateKey(PEM file)>\n");
        return 0;
    }
    
    srand(time(0));

    char SnKey[16] = { };
    GenerateSnKey(SnKey);

    double current_time
        = std::chrono::duration_cast<std::chrono::duration<double>>(
            std::chrono::system_clock::now().time_since_epoch()).count();

    BIO* BIO_file = BIO_new_file(argv[1], "r");
    if (BIO_file == nullptr) {
        printf("Failed to read file.\n");
        return -1;
    }

    RSA* PrivateKey = PEM_read_bio_RSAPrivateKey(BIO_file, nullptr, nullptr, nullptr);
    if (PrivateKey == nullptr) {
        printf("Failed to load private key.\n");
        return -2;
    }

    BIO_free_all(BIO_file);

    std::string Name;
    std::string Organization;
    std::cout << "Your name: ";
    std::getline(std::cin, Name);
    std::cout << "Yout organization: ";
    std::getline(std::cin, Organization);

    std::string buffer;
    printf("Input Request Code (in Base64), empty line to return:\n");
    while(true) {
        std::string temp;
        std::getline(std::cin, temp);
        buffer += temp;
        if (temp.empty())
            break;
    }

    unsigned char enc_data[1024] = { };
    char data[1024] = { };

    std::string DeviceIdentifier("");
    EVP_DecodeBlock(enc_data, reinterpret_cast<const unsigned char*>(buffer.c_str()), buffer.length());
    if (RSA_private_decrypt(256, enc_data, reinterpret_cast<unsigned char*>(data), PrivateKey, RSA_PKCS1_PADDING) == -1) {
        printf("Failed to decrypt data.\n");
        return -3;
    }
#ifdef _DEBUG
    printf("-----------Begin Request Code Data---------------\n");
    printf("%s\n", data);
    printf("-----------End Request Code Data---------------\n");
#endif
    // Get DeviceIdentifier from data.
    for (int i = 0, length = strlen(data) - 4; i < length; ++i) {
        if(data[i] == '"' &&
           data[i + 1] == 'D' &&
           data[i + 2] == 'I' &&
           data[i + 3] == '"') {
            
            char temp[256] = { };
            int x = i + 4, j = 0;
            while (data[x] != '"' && x < length)
                x++;
            x++;
            while (data[x] != '"' && j < 256) {
                temp[j++] = data[x];
                x++;
            }
            DeviceIdentifier += temp;
            break;
        }
    }

    memset(data, 0, sizeof(data));
    memset(enc_data, 0, sizeof(enc_data));
    
    snprintf(data, sizeof(data), "{\n  \"DI\" : \"%s\", \n  \"T\" : \"%lf\", \n  \"K\" : \"%.16s\", \n  \"N\" : \"%s\", \n  \"O\" : \"%s\"\n}",
        DeviceIdentifier.c_str(),
        current_time,
        SnKey,
        Name.c_str(),
        Organization.c_str()
    );
    
#ifdef _DEBUG
    printf("-----------Begin Activation Code Data---------------\n");
    printf("%s\n", data);
    printf("-----------End Activation Code Data---------------\n");
#endif
    
    RSA_private_encrypt(strlen(data), reinterpret_cast<unsigned char*>(data), enc_data, PrivateKey, RSA_PKCS1_PADDING);

    char result[1024] = { };
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result), enc_data, 256);
    printf("Activation Code:\n%s\n", result);

    RSA_free(PrivateKey);
    return 0;
}
