#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>

#ifndef UNICODE
#include <stdio.h>
#endif

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/des.h>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "libcrypto.lib")

#define NAVICAT_12

void GenerateSnKey(char(&SnKey)[16]) {
    static char EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static DES_cblock DESKey = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };

    BYTE temp_snKey[10] = { 0x68, 0x2a };   //  must start with 0x68, 0x2a
    temp_snKey[2] = rand();
    temp_snKey[3] = rand();
    temp_snKey[4] = rand();
    temp_snKey[5] = 0xCE;   //  Must be 0xCE for Simplified Chinese version.
                            //  Must be 0xAA for Traditional Chinese version.

    temp_snKey[6] = 0x32;   //  Must be 0x32 for Simplified Chinese version.
                            //  Must be 0x99 for Traditional Chinese version.

#if defined(NAVICAT_12)
    temp_snKey[7] = 0x65;   //  0x65 - commercial, 0x66 - non-commercial
    temp_snKey[8] = 0xC0;   //  High 4-bits = version number. Low 4-bits doesn't know, but can be used to delay activation time.
#elif defined(NAVICAT_11)
    temp_snKey[7] = 0x15;   //  0x15 - commercial, 0x16 - non-commercial
    temp_snKey[8] = 0xB0;   //  High 4-bits = version number. Low 4-bits doesn't know, but can be used to delay activation time.
#endif
    temp_snKey[9] = 0x70;   //  0xfd, 0xfc, 0xfb if you want to use not-for-resale license.

    DES_key_schedule schedule;
    DES_set_key_unchecked(&DESKey, &schedule);
    DES_cblock enc_temp_snKey;

    DES_ecb_encrypt(reinterpret_cast<const_DES_cblock*>(temp_snKey + 2), &enc_temp_snKey, &schedule, DES_ENCRYPT);
    memmove_s(temp_snKey + 2, sizeof(enc_temp_snKey), enc_temp_snKey, sizeof(enc_temp_snKey));

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

    _tprintf_s(TEXT("\r\n"));
    _tprintf_s(TEXT("SnKey:\r\n"));
    _tprintf_s(TEXT("%.4hs-%.4hs-%.4hs-%.4hs\r\n"), SnKey, SnKey + 4, SnKey + 8, SnKey + 12);
    _tprintf_s(TEXT("\r\n"));
}

BOOL GenerateLicense(RSA* RSAPrivateKey,
                     const char* SnKey,
                     const char* Name,
                     const char* Organization,
                     const char* DI) {

    char LicenseJson[2048 / 8] = { };
#if defined(NAVICAT_12)
    sprintf_s(LicenseJson, "{\"K\":\"%.16s\", \"N\":\"%s\", \"O\":\"%s\", \"DI\":\"%s\"}", SnKey, Name, Organization, DI);
#elif defined(NAVICAT_11)
    sprintf_s(LicenseJson, "{\"K\":\"%.16s\", \"N\":\"%s\", \"O\":\"%s\"}", SnKey, Name, Organization);
#endif
    unsigned char License[2048 / 8] = { };
    RSA_private_encrypt(strlen(LicenseJson),
                        reinterpret_cast<uint8_t*>(LicenseJson),
                        License,
                        RSAPrivateKey,
                        RSA_PKCS1_PADDING);

#if defined(NAVICAT_12)
    DWORD LicenseStringLength = 1024;
    TCHAR LicenseString[1024] = { };
    if (!CryptBinaryToString(License, sizeof(License), CRYPT_STRING_BASE64, LicenseString, &LicenseStringLength)) {
        _tprintf_s(TEXT("Cannot get Base64 string. CODE: 0x%08x\r\n"), GetLastError());
        return FALSE;
    }

    _tprintf_s(TEXT("License:\r\n%s"), LicenseString);
    return TRUE;
#elif defined(NAVICAT_11)
    HANDLE hLicenseFile = CreateFile(TEXT("license_file"), GENERIC_ALL, NULL, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hLicenseFile == NULL)
        return FALSE;

    if (!WriteFile(hLicenseFile, License, sizeof(License), nullptr, nullptr)) {
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
        return -1;
    }

    srand(time(nullptr));

#ifdef UNICODE
    char pem_file_path[256] = { };
    sprintf_s(pem_file_path, "%S", argv[1]);
#else
    char* pem_file_path = argv[1];
#endif

    RSA* PrivateKey = nullptr;
    BIO* PrivateKeyFile = BIO_new(BIO_s_file());
    BIO_read_filename(PrivateKeyFile, pem_file_path);
    PrivateKey = PEM_read_bio_RSAPrivateKey(PrivateKeyFile, nullptr, nullptr, nullptr);
    BIO_free_all(PrivateKeyFile);

    if (PrivateKey == nullptr) {
        _tprintf_s(TEXT("Failed to load private key.\r\n"));
        return -2;
    }

    TCHAR tName[64] = { };
    TCHAR tOrganization[64] = { };
    {
        DWORD ReadCount;

        _tprintf_s(TEXT("Your name: "));
        ReadConsole(GetStdHandle(STD_INPUT_HANDLE), tName, 64, &ReadCount, nullptr);
        tName[ReadCount - 2] = 0;
        tName[ReadCount - 1] = 0;
        _tprintf_s(TEXT("Your organization: "));
        ReadConsole(GetStdHandle(STD_INPUT_HANDLE), tOrganization, 64, &ReadCount, nullptr);
        tOrganization[ReadCount - 2] = 0;
        tOrganization[ReadCount - 1] = 0;
    }

#ifdef UNICODE
    char Name[64] = { };
    char Organization[64] = { };

    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                            tName, _tcslen(tName),
                            Name, 64,
                            NULL,
                            NULL) == 0) {
        _tprintf_s(TEXT("Failed to convert name to UTF-8. CODE: 0x%08x\r\n"), GetLastError());
        RSA_free(PrivateKey);
        return GetLastError();
    }

    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                            tOrganization, _tcslen(tOrganization),
                            Organization, 64,
                            NULL,
                            NULL) == 0) {
        _tprintf_s(TEXT("Failed to convert name to UTF-8. CODE: 0x%08x\r\n"), GetLastError());
        RSA_free(PrivateKey);
        return GetLastError();
    }
#else
    char* Name = tName;
    char* Organization = tOrganization;
#endif

    char SnKey[16] = { };
    GenerateSnKey(SnKey);

    TCHAR Base64String[1024] = { };
    _tprintf_s(TEXT("Input request code (in Base64), empty line to return:\r\n"));
    for (TCHAR* cur = Base64String; cur < Base64String + 1024;) {
        DWORD ReadCount;
        if (!ReadConsole(GetStdHandle(STD_INPUT_HANDLE), cur, Base64String + 1024 - cur, &ReadCount, NULL))
            break;

        cur += ReadCount;
#ifdef UNICODE
        if (*reinterpret_cast<uint32_t*>(cur - 4) == '\r\0\n\0')
            break;
#else
        if (*reinterpret_cast<uint32_t*>(cur - 4) == '\r\n\r\n')
            break;
#endif
    }
    Base64String[1024 - 1] = NULL;

    BYTE enc_request_code[1024] = { };
    DWORD enc_request_code_length = 1024;
    if (!CryptStringToBinary(Base64String, NULL, CRYPT_STRING_BASE64, enc_request_code, &enc_request_code_length, NULL, NULL)) {
        _tprintf_s(TEXT("Failed to decode Base64 string. CODE: 0x%08x\r\n"), GetLastError());
        RSA_free(PrivateKey);
        return GetLastError();
    }

    char request_code[1024] = { };
    if (!RSA_private_decrypt(enc_request_code_length,
                             enc_request_code,
                             reinterpret_cast<BYTE*>(request_code),
                             PrivateKey, RSA_PKCS1_PADDING)) {
        _tprintf_s(TEXT("Failed to decrypt request code.\r\n"));
        RSA_free(PrivateKey);
        return -3;
    }

#ifdef _DEBUG
#ifdef UNICODE
    _tprintf_s(TEXT("%S\r\n"), request_code);
#else
    _tprintf_s(TEXT("%s\r\n"), request_code);
#endif
#endif

    //--------------------------------------------------------------------

    if (strlen(request_code) >= 256) {
        _tprintf_s(TEXT("Not a valid request code.\r\n"));
        RSA_free(PrivateKey);
        return -4;
    }

    char* DI_ptr = request_code;
    for (; DI_ptr < request_code + 256; DI_ptr++) {
        if (*reinterpret_cast<uint32_t*>(DI_ptr) == '"ID"') {
            DI_ptr += 4;
            while (*DI_ptr++ != '"');
            break;
        }
    }

    if (DI_ptr >= request_code + 256) {
        _tprintf_s(TEXT("Not a valid request code.\r\n"));
        RSA_free(PrivateKey);
        return -5;
    }

    for (char* ptr = DI_ptr; ptr < request_code + 256; ptr++) {
        if (*ptr == '"') {
            *ptr = 0;
            break;
        }
    }

    //-------------------------------------------------------------------

    GenerateLicense(PrivateKey, SnKey, Name, Organization, DI_ptr);

    RSA_free(PrivateKey);
    return 0;
}
