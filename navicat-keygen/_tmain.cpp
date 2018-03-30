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

// OpenSSL precompiled lib, download from https://www.npcglib.org/~stathis/blog/precompiled-openssl/, MSVC2015 version
// direct link https://www.npcglib.org/~stathis/downloads/openssl-1.1.0f-vs2015.7z
// x86: "D:\openssl-1.1.0f-vs2015\include" has been add to include path.    (modify it at project properties if necessary)
//      "D:\openssl-1.1.0f-vs2015\lib" has been add to library path.        (modify it at project properties if necessary)
// x64: "D:\openssl-1.1.0f-vs2015\include64" has been add to include path.  (modify it at project properties if necessary)
//      "D:\openssl-1.1.0f-vs2015\lib64" has been add to library path.      (modify it at project properties if necessary)
#ifdef _DEBUG
#pragma comment(lib, "libcryptoMTd.lib")
#else
#pragma comment(lib, "libcryptoMT.lib")
#endif
#pragma comment(lib, "WS2_32.lib")      // some symbol are used in OpenSSL lib
#pragma comment(lib, "Crypt32.lib")     // some symbol are used in OpenSSL lib

#define NAVICAT_12

enum NavicatLanguage {
    English,
    SimplifiedChinese,
    TraditionalChinese,
    Japanese,
    Polish,
    Spanish,
    French,
    German,
    Korean,
    Russian,
    Portuguese
};

void GenerateSnKey(char(&SnKey)[16], NavicatLanguage _language) {
    static char EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static DES_cblock DESKey = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };

    BYTE temp_SnKey[10] = { 0x68, 0x2a };   //  must start with 0x68, 0x2a
    temp_SnKey[2] = rand();
    temp_SnKey[3] = rand();
    temp_SnKey[4] = rand();

    switch (_language) {
        case English:
            temp_SnKey[5] = 0xAC;       // Must be 0xAC for English version.
            temp_SnKey[6] = 0x88;       // Must be 0x88 for English version.
            break;
        case SimplifiedChinese:
            temp_SnKey[5] = 0xCE;       // Must be 0xCE for Simplified Chinese version.
            temp_SnKey[6] = 0x32;       // Must be 0x32 for Simplified Chinese version.
            break;
        case TraditionalChinese:
            temp_SnKey[5] = 0xAA;       // Must be 0xAA for Traditional Chinese version.
            temp_SnKey[6] = 0x99;       // Must be 0x99 for Traditional Chinese version.
            break;
        case Japanese:
            temp_SnKey[5] = 0xAD;       // Must be 0xAD for Japanese version. Discoverer: @dragonflylee
            temp_SnKey[6] = 0x82;       // Must be 0x82 for Japanese version. Discoverer: @dragonflylee
            break;
        case Polish:
            temp_SnKey[5] = 0xBB;       // Must be 0xBB for Polish version. Discoverer: @dragonflylee
            temp_SnKey[6] = 0x55;       // Must be 0x55 for Polish version. Discoverer: @dragonflylee
            break;
        case Spanish:
            temp_SnKey[5] = 0xAE;       // Must be 0xAE for Spanish version. Discoverer: @dragonflylee
            temp_SnKey[6] = 0x10;       // Must be 0x10 for Spanish version. Discoverer: @dragonflylee
            break;
        case French:
            temp_SnKey[5] = 0xFA;       // Must be 0xFA for French version. Discoverer: @Deltafox79
            temp_SnKey[6] = 0x20;       // Must be 0x20 for French version. Discoverer: @Deltafox79
            break;
        case German:
            temp_SnKey[5] = 0xB1;       // Must be 0xB1 for German version. Discoverer: @dragonflylee
            temp_SnKey[6] = 0x60;       // Must be 0x60 for German version. Discoverer: @dragonflylee
            break;
        case Korean:
            temp_SnKey[5] = 0xB5;       // Must be 0xB5 for Korean version. Discoverer: @dragonflylee
            temp_SnKey[6] = 0x60;       // Must be 0x60 for Korean version. Discoverer: @dragonflylee
            break;
        case Russian:
            temp_SnKey[5] = 0xEE;       // Must be 0xB5 for Russian version. Discoverer: @dragonflylee
            temp_SnKey[6] = 0x16;       // Must be 0x60 for Russian version. Discoverer: @dragonflylee
            break;
        case Portuguese:
            temp_SnKey[5] = 0xCD;       // Must be 0xCD for Portuguese version. Discoverer: @dragonflylee
            temp_SnKey[6] = 0x49;       // Must be 0x49 for Portuguese version. Discoverer: @dragonflylee
            break;
        default:
            break;
    }

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

RSA* ReadRSAPrivateKeyFromFile(LPCTSTR filename) {
#ifdef UNICODE
    int req_size = WideCharToMultiByte(CP_ACP, 0, filename, -1, nullptr, 0, nullptr, nullptr);
    if (req_size == 0) {
        _tprintf_s(TEXT("Failed to convert wchar* to char*. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> WideCharToMultiByte]\r\n"), GetLastError());
        return FALSE;
    }

    char* temp_filename = new char[req_size]();
    WideCharToMultiByte(CP_ACP, 0, filename, -1, temp_filename, req_size, nullptr, nullptr);

    BIO* b = BIO_new(BIO_s_file());
    if (b == nullptr) {
        _tprintf_s(TEXT("Failed to create BIO object. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> BIO_new]\r\n"), ERR_get_error());
        delete[] temp_filename;
        return FALSE;
    }

    if (1 != BIO_read_filename(b, temp_filename)) {
        _tprintf_s(TEXT("Failed to set target file of BIO. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> BIO_read_filename]\r\n"), ERR_get_error());

        BIO_free_all(b);
        delete[] temp_filename;
        return FALSE;
    }

    delete[] temp_filename;
#else
    BIO* b = BIO_new(BIO_s_file());
    if (b == nullptr) {
        _tprintf_s(TEXT("Failed to create BIO object. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> BIO_new]\r\n"), ERR_get_error());
        return FALSE;
    }

    if (1 != BIO_read_filename(b, filename)) {
        _tprintf_s(TEXT("Failed to set target file of BIO. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> BIO_read_filename]\r\n"), ERR_get_error());

        BIO_free_all(b);
        return FALSE;
    }
#endif
    RSA* ret = PEM_read_bio_RSAPrivateKey(b, nullptr, nullptr, nullptr);
    if (ret == nullptr) {
        _tprintf_s(TEXT("Failed to read RSA private key. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> PEM_read_bio_RSAPrivateKey]\r\n"), ERR_get_error());

        BIO_free_all(b);
        return nullptr;
    } else {
        BIO_free_all(b);
        return ret;
    }
}

int _tmain(int argc, TCHAR* argv[]) {
    if (argc != 2) {
        _tprintf_s(TEXT("Usage:\r\n"));
        _tprintf_s(TEXT("    navicat-keygen.exe <RSA-2048 PrivateKey(PEM file)>\r\n"));
        return 0;
    }

    srand(static_cast<unsigned int>(time(nullptr)));

    RSA* PrivateKey = ReadRSAPrivateKeyFromFile(argv[1]);
    if (PrivateKey == nullptr) 
        return 0;

    std::cout
        << "Which is your Navicat language?" << std::endl
        << "0. English" << std::endl
        << "1. Simplified Chinese" << std::endl
        << "2. Traditional Chinese" << std::endl
        << "3. Japanese" << std::endl
        << "4. Polish" << std::endl
        << "5. Spanish" << std::endl
        << "6. French" << std::endl
        << "7. German" << std::endl
        << "8. Korean" << std::endl
        << "9. Russian" << std::endl
        << "10. Portuguese" << std::endl
        << std::endl;

    int LanguageIndex = -1;
    while (true) {
        std::cout << "(input index)>";

        std::string temp;
        if (!std::getline(std::cin, temp)) {
            RSA_free(PrivateKey);
            return 0;
        }
        try {
            LanguageIndex = std::stoi(temp);
            if (LanguageIndex < 0 || LanguageIndex > 10)
                throw std::invalid_argument("Invalid index");
            break;
        } catch (...) {
            std::cout << "Invalid index." << std::endl;
            continue;
        }
    }

    char SnKey[16] = { };
    GenerateSnKey(SnKey, static_cast<NavicatLanguage>(LanguageIndex));

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
