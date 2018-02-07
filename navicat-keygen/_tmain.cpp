#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>

#include <iostream>
#include <string>

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/des.h>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "libcrypto.lib")

#define NAVICAT_12
#define NAVICAT_CHS

void GenerateSnKey(char(&SnKey)[16]) {
    static char EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static DES_cblock DESKey = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };

    BYTE temp_SnKey[10] = { 0x68, 0x2a };   //  must start with 0x68, 0x2a
    temp_SnKey[2] = rand();
    temp_SnKey[3] = rand();
    temp_SnKey[4] = rand();

#if defined(NAVICAT_ENG)
    temp_SnKey[5] = 0xAC;       // Must be 0xAC for English version.
    temp_SnKey[6] = 0x88;       // Must be 0x88 for English version.
#elif defined(NAVICAT_CHS)
    temp_SnKey[5] = 0xCE;       // Must be 0xCE for Simplified Chinese version.
    temp_SnKey[6] = 0x32;       // Must be 0x32 for Simplified Chinese version.
#elif defined(NAVICAT_CHT)
    temp_SnKey[5] = 0xAA;       // Must be 0xAA for Traditional Chinese version.
    temp_SnKey[6] = 0x99;       // Must be 0x99 for Traditional Chinese version.
#elif defined(NAVICAT_FRE)
    temp_SnKey[5] = 0xFA;       // Must be 0xFA for French version. Discoverer: @Deltafox79
    temp_SnKey[6] = 0x20;       // Must be 0x20 for French version. Discoverer: @Deltafox79
#else
#error "Navicat product type is not specified."
#endif

#if defined(NAVICAT_12)
    temp_SnKey[7] = 0x65;   //  0x65 - commercial, 0x66 - non-commercial
    temp_SnKey[8] = 0xC0;   //  High 4-bits = version number. Low 4-bits doesn't know, but can be used to delay activation time.
#elif defined(NAVICAT_11)
    temp_SnKey[7] = 0x15;   //  0x15 - commercial, 0x16 - non-commercial
    temp_SnKey[8] = 0xB0;   //  High 4-bits = version number. Low 4-bits doesn't know, but can be used to delay activation time.
#else
#error "Navicat version is not specified."
#endif
    temp_SnKey[9] = 0x32;   // 0xFB is Not-For-Resale-30-days license.
                            // 0xFC is Not-For-Resale-90-days license.
                            // 0xFD is Not-For-Resale-365-days license.
                            // 0xFE is Not-For-Resale license.
                            // 0xFF is Site license.
                            // Must not be 0x00. 0x01-0xFA is ok.

    DES_key_schedule schedule;
    DES_set_key_unchecked(&DESKey, &schedule);
    DES_cblock enc_temp_snKey;

    DES_ecb_encrypt(reinterpret_cast<const_DES_cblock*>(temp_SnKey + 2), &enc_temp_snKey, &schedule, DES_ENCRYPT);
    memmove_s(temp_SnKey + 2, sizeof(enc_temp_snKey), enc_temp_snKey, sizeof(enc_temp_snKey));

    SnKey[0] = EncodeTable[temp_SnKey[0] >> 3];
    SnKey[1] = EncodeTable[(temp_SnKey[0] & 0x07) << 2 | temp_SnKey[1] >> 6];
    SnKey[2] = EncodeTable[temp_SnKey[1] >> 1 & 0x1F];
    SnKey[3] = EncodeTable[(temp_SnKey[1] & 0x1) << 4 | temp_SnKey[2] >> 4];
    SnKey[4] = EncodeTable[(temp_SnKey[2] & 0xF) << 1 | temp_SnKey[3] >> 7];
    SnKey[5] = EncodeTable[temp_SnKey[3] >> 2 & 0x1F];
    SnKey[6] = EncodeTable[temp_SnKey[3] << 3 & 0x1F | temp_SnKey[4] >> 5];
    SnKey[7] = EncodeTable[temp_SnKey[4] & 0x1F];

    SnKey[8] = EncodeTable[temp_SnKey[5] >> 3];
    SnKey[9] = EncodeTable[(temp_SnKey[5] & 0x07) << 2 | temp_SnKey[6] >> 6];
    SnKey[10] = EncodeTable[temp_SnKey[6] >> 1 & 0x1F];
    SnKey[11] = EncodeTable[(temp_SnKey[6] & 0x1) << 4 | temp_SnKey[7] >> 4];
    SnKey[12] = EncodeTable[(temp_SnKey[7] & 0xF) << 1 | temp_SnKey[8] >> 7];
    SnKey[13] = EncodeTable[temp_SnKey[8] >> 2 & 0x1F];
    SnKey[14] = EncodeTable[temp_SnKey[8] << 3 & 0x1F | temp_SnKey[9] >> 5];
    SnKey[15] = EncodeTable[temp_SnKey[9] & 0x1F];

    _tprintf_s(TEXT("\r\n"));
    _tprintf_s(TEXT("SnKey:\r\n"));
    _tprintf_s(TEXT("%.4hs-%.4hs-%.4hs-%.4hs\r\n"), SnKey, SnKey + 4, SnKey + 8, SnKey + 12);
    _tprintf_s(TEXT("\r\n"));
}

BOOL GenerateLicense(RSA* RSAPrivateKey,
                     const char* SnKey,
                     const char* Name,
                     const char* Organization,
                     const char* DeviceIdentifier) {

    char LicenseJson[2048 / 8] = { };
#if defined(NAVICAT_12)
    sprintf_s(LicenseJson, "{\"K\":\"%.16s\", \"N\":\"%s\", \"O\":\"%s\", \"DI\":\"%s\"}", SnKey, Name, Organization, DeviceIdentifier);
#elif defined(NAVICAT_11)
    sprintf_s(LicenseJson, "{\"K\":\"%.16s\", \"N\":\"%s\", \"O\":\"%s\"}", SnKey, Name, Organization);
#else
#error "Navicat version is not specified."
#endif
    unsigned char EncryptedLicenseData[2048 / 8] = { };
    if (RSA_private_encrypt(static_cast<int>(strlen(LicenseJson)),
                            reinterpret_cast<uint8_t*>(LicenseJson),
                            EncryptedLicenseData,
                            RSAPrivateKey,
                            RSA_PKCS1_PADDING) == -1) {
        _tprintf_s(TEXT("Failed to encrypt license data.\r\n"));
        return FALSE;
    }

#if defined(NAVICAT_12)
    DWORD LicenseStringLength = 1024;
    TCHAR LicenseString[1024] = { };
    if (!CryptBinaryToString(EncryptedLicenseData, sizeof(EncryptedLicenseData), CRYPT_STRING_BASE64, LicenseString, &LicenseStringLength)) {
        _tprintf_s(TEXT("Cannot get Base64 string. CODE: 0x%08x\r\n"), GetLastError());
        return FALSE;
    }

    _tprintf_s(TEXT("License:\r\n%s"), LicenseString);
    return TRUE;
#elif defined(NAVICAT_11)
    HANDLE hLicenseFile = CreateFile(TEXT("license_file"), GENERIC_ALL, NULL, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hLicenseFile == NULL) {
        _tprintf_s(TEXT("Failed to create \"license_file\".\r\n"));
        return FALSE;
    }

    if (!WriteFile(hLicenseFile, EncryptedLicenseData, sizeof(EncryptedLicenseData), nullptr, nullptr)) {
        _tprintf_s(TEXT("Failed to write \"license_file\".\r\n"));
        CloseHandle(hLicenseFile);
        return FALSE;
    }

    CloseHandle(hLicenseFile);
    return TRUE;
#endif
}

int _tmain(int argc, TCHAR* argv[]) {
    if (argc != 2) {
        _tprintf_s(TEXT("Usage:\r\n"));
        _tprintf_s(TEXT("    navicat-keygen.exe <RSA-2048 PrivateKey(PEM file)>\r\n"));
        return 0;
    }

    srand(static_cast<unsigned int>(time(nullptr)));
#ifdef UNICODE
    char pem_file_path[MAX_PATH] = { };
    sprintf_s(pem_file_path, "%S", argv[1]);
#else
    char* pem_file_path = argv[1];
#endif

    RSA* PrivateKey = nullptr;
    {
        BIO* PrivateKeyFile = BIO_new(BIO_s_file());
        BIO_read_filename(PrivateKeyFile, pem_file_path);
        PrivateKey = PEM_read_bio_RSAPrivateKey(PrivateKeyFile, nullptr, nullptr, nullptr);
        BIO_free_all(PrivateKeyFile);
    }

    if (PrivateKey == nullptr) {
        _tprintf_s(TEXT("Failed to load private key.\r\n"));
        return -1;
    }

    char SnKey[16] = { };
    GenerateSnKey(SnKey);

    std::string strName;
    std::string strOrganization;
    _tprintf_s(TEXT("Your name: "));
    std::getline(std::cin, strName);
    _tprintf_s(TEXT("Your organization: "));
    std::getline(std::cin, strOrganization);

#if defined(NAVICAT_12)
    std::string RequestCode;
    _tprintf_s(TEXT("Input request code (in Base64), empty line to return:\r\n"));
    while (true) {
        std::string temp;
        std::getline(std::cin, temp);
        if (temp.empty())
            break;

        RequestCode += temp;
    }
    
    BYTE EncryptedRequestData[1024] = { };
    DWORD EncryptedRequestDataLength = sizeof(EncryptedRequestData);
    if (!CryptStringToBinaryA(RequestCode.c_str(), NULL, CRYPT_STRING_BASE64, EncryptedRequestData, &EncryptedRequestDataLength, NULL, NULL)) {
        _tprintf_s(TEXT("Failed to decode Base64 string. CODE: 0x%08x\r\n"), GetLastError());
        RSA_free(PrivateKey);
        return GetLastError();
    }

    char RequestData[1024] = { };
    if (RSA_private_decrypt(EncryptedRequestDataLength,
                             EncryptedRequestData,
                             reinterpret_cast<BYTE*>(RequestData),
                             PrivateKey, RSA_PKCS1_PADDING) == -1) {
        _tprintf_s(TEXT("Failed to decrypt request code.\r\n"));
        RSA_free(PrivateKey);
        return -2;
    }

#ifdef _DEBUG
    std::cout << "-----------Begin Request Code Data---------------" << std::endl;
    std::cout << RequestData << std::endl;
    std::cout << "-----------End Request Code Data---------------" << std::endl;
#endif

    //--------------------------------------------------------------------
    std::string strDeviceIdentifier;
    for (int i = 0, length = static_cast<int>(strlen(RequestData)) - 4; i < length; ++i) {
        if (RequestData[i] == '"' &&
            RequestData[i + 1] == 'D' &&
            RequestData[i + 2] == 'I' &&
            RequestData[i + 3] == '"') {

            char temp[256] = { };
            int x = i + 4, j = 0;
            while (RequestData[x] != '"' && x < length)
                x++;
            x++;
            while (RequestData[x] != '"' && j < 256) {
                temp[j++] = RequestData[x];
                x++;
            }
            strDeviceIdentifier += temp;
            break;
        }
    }

    if (strDeviceIdentifier.empty()) {
        _tprintf_s(TEXT("Not a valid request code.\r\n"));
        RSA_free(PrivateKey);
        return -3;
    }

    //-------------------------------------------------------------------

    GenerateLicense(PrivateKey, SnKey, strName.c_str(), strOrganization.c_str(), strDeviceIdentifier.c_str());
#elif defined(NAVICAT_11)
    GenerateLicense(PrivateKey, SnKey, strName.c_str(), strOrganization.c_str(), nullptr);
#else
#error "Navicat version is not specified."
#endif

    RSA_free(PrivateKey);
    return 0;
}
