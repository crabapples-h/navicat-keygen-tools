#include <iostream>
#include <ctime>

#include <tchar.h>
#include <windows.h>

#include "NavicatKeygen.hpp"

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

bool ConvertToUTF8(LPCSTR from, std::string& to) {
    bool bSuccess = false;
    int len = 0;
    LPWSTR lpUnicodeString = nullptr;

    len = MultiByteToWideChar(CP_ACP, NULL, from, -1, NULL, 0);
    if (len == 0)
        goto ON_ConvertToUTF8_0_ERROR;

    lpUnicodeString = reinterpret_cast<LPWSTR>(HeapAlloc(GetProcessHeap(),
                                                         HEAP_ZERO_MEMORY,
                                                         len * sizeof(WCHAR)));
    if (lpUnicodeString == nullptr)
        goto ON_ConvertToUTF8_0_ERROR;

    if (!MultiByteToWideChar(CP_ACP, NULL, from, -1, lpUnicodeString, len))
        goto ON_ConvertToUTF8_0_ERROR;

    len = WideCharToMultiByte(CP_UTF8, NULL, lpUnicodeString, -1, NULL, 0, NULL, NULL);
    if (len == 0)
        goto ON_ConvertToUTF8_0_ERROR;

    to.resize(len);
    if (!WideCharToMultiByte(CP_UTF8, NULL, lpUnicodeString, -1, to.data(), len, NULL, NULL))
        goto ON_ConvertToUTF8_0_ERROR;

    while (to.back() == 0)
        to.pop_back();

    bSuccess = true;

ON_ConvertToUTF8_0_ERROR:
    if (lpUnicodeString)
        HeapFree(GetProcessHeap(), NULL, lpUnicodeString);
    return bSuccess;
}

bool ConvertToUTF8(LPCWSTR from, std::string& to) {
    bool bSuccess = false;
    int len = 0;

    len = WideCharToMultiByte(CP_UTF8, NULL, from, -1, NULL, 0, NULL, NULL);
    if (len == 0)
        goto ON_ConvertToUTF8_1_ERROR;

    to.resize(len);
    if (!WideCharToMultiByte(CP_UTF8, NULL, from, -1, to.data(), len, NULL, NULL))
        goto ON_ConvertToUTF8_1_ERROR;

    while (to.back() == 0)
        to.pop_back();

    bSuccess = true;

ON_ConvertToUTF8_1_ERROR:
    return bSuccess;
}

bool ConvertToUTF8(std::string& str) {
    bool bSuccess = false;

    std::string temp;
    bSuccess = ConvertToUTF8(str.c_str(), temp);
    if (!bSuccess)
        return false;

    str = temp;
    return true;
}

std::string Base64Encode(const std::vector<uint8_t>& bytes) {
    std::string Result;
    DWORD pcchString = 0;

    if (bytes.empty())
        return Result;

    CryptBinaryToStringA(bytes.data(),
                         bytes.size(),
                         CRYPT_STRING_BASE64,
                         NULL,
                         &pcchString);
    if (pcchString == 0)
        return Result;

    Result.resize(pcchString + 1);

    if (!CryptBinaryToStringA(bytes.data(),
                              bytes.size(),
                              CRYPT_STRING_BASE64,
                              Result.data(),
                              &pcchString))
        Result.clear();

    return Result;
}

std::vector<uint8_t> Base64Decode(std::string& str) {
    std::vector<uint8_t> Result;
    DWORD pcbBinary = 0;

    if (str.empty())
        return Result;

    CryptStringToBinaryA(str.c_str(),
                         NULL,
                         CRYPT_STRING_BASE64,
                         NULL,
                         &pcbBinary,
                         NULL,
                         NULL);
    if (pcbBinary == 0)
        return Result;

    Result.resize(pcbBinary);

    if (!CryptStringToBinaryA(str.c_str(),
                              NULL,
                              CRYPT_STRING_BASE64,
                              Result.data(),
                              &pcbBinary,
                              NULL,
                              NULL))
        Result.clear();

    return Result;
}

void help() {
    std::cout << "Usage:" << std::endl;
    std::cout << "  navicat-keygen.exe <RSA-2048 PrivateKey(PEM file)>" << std::endl;
}

bool GatherInformation(NavicatKeygen::Product& product,
                       NavicatKeygen::Language& language,
                       uint8_t& version) {
    int index = -1;
    std::string temp;

    std::cout << "Select Navicat product:" << std::endl
        << "0. DataModeler" << std::endl
        << "1. Premium" << std::endl
        << "2. MySQL" << std::endl
        << "3. PostgreSQL" << std::endl
        << "4. Oracle" << std::endl
        << "5. SQLServer" << std::endl
        << "6. SQLite" << std::endl
        << "7. MariaDB" << std::endl
        << std::endl;

    while (true) {
        std::cout << "(input index)> ";
        if (!std::getline(std::cin, temp)) {
            return false;
        }

        try {
            index = std::stoi(temp);
            switch (index) {
                case 0:
                    product = NavicatKeygen::Product::DataModeler;
                    break;
                case 1:
                    product = NavicatKeygen::Product::Premium;
                    break;
                case 2:
                    product = NavicatKeygen::Product::MySQL;
                    break;
                case 3:
                    product = NavicatKeygen::Product::PostgreSQL;
                    break;
                case 4:
                    product = NavicatKeygen::Product::Oracle;
                    break;
                case 5:
                    product = NavicatKeygen::Product::SQLServer;
                    break;
                case 6:
                    product = NavicatKeygen::Product::SQLite;
                    break;
                case 7:
                    product = NavicatKeygen::Product::MariaDB;
                    break;
                default:
                    throw std::invalid_argument("Invalid index");
            }
            break;
        } catch (...) {
            std::cout << "Invalid index." << std::endl;
            continue;
        }
    }

    std::cout << std::endl;
    std::cout << "Select product language:" << std::endl
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

    while (true) {
        std::cout << "(input index)> ";
        if (!std::getline(std::cin, temp)) {
            return false;
        }

        try {
            index = std::stoi(temp);
            switch (index) {
                case 0:
                    language = NavicatKeygen::Language::English;
                    break;
                case 1:
                    language = NavicatKeygen::Language::SimplifiedChinese;
                    break;
                case 2:
                    language = NavicatKeygen::Language::TraditionalChinese;
                    break;
                case 3:
                    language = NavicatKeygen::Language::Japanese;
                    break;
                case 4:
                    language = NavicatKeygen::Language::Polish;
                    break;
                case 5:
                    language = NavicatKeygen::Language::Spanish;
                    break;
                case 6:
                    language = NavicatKeygen::Language::French;
                    break;
                case 7:
                    language = NavicatKeygen::Language::German;
                    break;
                case 8:
                    language = NavicatKeygen::Language::Korean;
                    break;
                case 9:
                    language = NavicatKeygen::Language::Russian;
                    break;
                case 10:
                    language = NavicatKeygen::Language::Portuguese;
                    break;
                default:
                    throw std::invalid_argument("Invalid index");
            }
            break;
        } catch (...) {
            std::cout << "Invalid index." << std::endl;
            continue;
        }
    }

    std::cout << std::endl;
    while (true) {
        std::cout << "(input major version number)> ";
        if (!std::getline(std::cin, temp)) {
            return false;
        }

        try {
            version = std::stoi(temp);
            break;
        } catch (...) {
            std::cout << "Invalid index." << std::endl;
            continue;
        }
    }

    std::cout << std::endl;
}

int _tmain(int argc, LPTSTR argv[]) {
    if (argc != 2) {
        help();
        return 0;
    }

    std::string RSAPrivateKeyPath;
    RSACipher* cipher = nullptr;
    std::string RequestCode_b64;
    std::string ResponseCode_b64;
    std::vector<uint8_t> RequestCode;
    std::vector<uint8_t> ResponseCode;
    char RequestInfo[256] = {};
    char ResponseInfo[256] = {};

    rapidjson::Document json;

    NavicatKeygen keygen;
    NavicatKeygen::Product product;
    NavicatKeygen::Language language;
    uint8_t version = 0;
    std::string username;
    std::string organization;

    cipher = RSACipher::Create();
    if (cipher == nullptr) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "Failed to create RSACipher." << std::endl;
        goto ON_tmain_ERROR;
    }

    if (!ConvertToUTF8(argv[1], RSAPrivateKeyPath)) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ConvertToUTF8 fails." << std::endl;
        goto ON_tmain_ERROR;
    }

    if (!cipher->ImportKeyFromFile<RSACipher::KeyType::PrivateKey>(RSAPrivateKeyPath)) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ImportKeyFromFile fails." << std::endl;
        goto ON_tmain_ERROR;
    }

    GatherInformation(product, language, version);

    keygen.Generate(version, language, product);
    std::cout << "Serial number:" << std::endl;
    std::cout << keygen.GetFormatedKey() << std::endl;
    std::cout << std::endl;

    std::cout << "Your name: ";
    if (!std::getline(std::cin, username))
        goto ON_tmain_ERROR;
    if (!ConvertToUTF8(username)) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ConvertToUTF8 fails." << std::endl;
        goto ON_tmain_ERROR;
    }

    std::cout << "Your organization: ";
    if (!std::getline(std::cin, organization))
        goto ON_tmain_ERROR;
    if (!ConvertToUTF8(organization)) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ConvertToUTF8 fails." << std::endl;
        goto ON_tmain_ERROR;
    }

    std::cout << "Input request code (in Base64), input empty line to end:" << std::endl;
    while (true) {
        std::string temp;
        if (!std::getline(std::cin, temp))
            goto ON_tmain_ERROR;

        if (temp.empty())
            break;

        RequestCode_b64 += temp;
    }

    RequestCode = Base64Decode(RequestCode_b64);
    if (RequestCode.empty()) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "Base64Decode fails." << std::endl;
        goto ON_tmain_ERROR;
    }

    if (!cipher->Decrypt(RequestCode.data(),
                         RequestCode.size(),
                         RequestInfo,
                         RSA_PKCS1_PADDING)) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "Decrypt<RSACipher::KeyType::PrivateKey> fails." << std::endl;
        goto ON_tmain_ERROR;
    }

    std::cout << "Request Info:" << std::endl;
    std::cout << RequestInfo << std::endl << std::endl;

    json.Parse(RequestInfo);
    json.RemoveMember("P");

    {
        rapidjson::Value N_Key;
        rapidjson::Value N_Value;
        rapidjson::Value O_Key;
        rapidjson::Value O_Value;
        rapidjson::Value T_Key;
        rapidjson::Value T_Value;
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

        N_Key.SetString("N", 1);
        N_Value.SetString(username.c_str(), username.length());
        O_Key.SetString("O", 1);
        O_Value.SetString(organization.c_str(), organization.length());
        T_Key.SetString("T", 1);
        T_Value.SetUint(std::time(nullptr));

        json.AddMember(N_Key, N_Value, json.GetAllocator());
        json.AddMember(O_Key, O_Value, json.GetAllocator());
        json.AddMember(T_Key, T_Value, json.GetAllocator());

        json.Accept(writer);
        if (buffer.GetSize() > 240) {
            std::cout << "Response info too long." << std::endl;
            goto ON_tmain_ERROR;
        }

        memcpy(ResponseInfo, buffer.GetString(), buffer.GetSize());
    }

    std::cout << "Response Info:" << std::endl;
    std::cout << ResponseInfo << std::endl << std::endl;

    ResponseCode.resize(256);

    if (!cipher->Encrypt<RSACipher::KeyType::PrivateKey>(ResponseInfo,
                                                         strlen(ResponseInfo),
                                                         ResponseCode.data(),
                                                         RSA_PKCS1_PADDING)) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "Encrypt<RSACipher::KeyType::PrivateKey> fails." << std::endl;
        goto ON_tmain_ERROR;
    }

    ResponseCode_b64 = Base64Encode(ResponseCode);
    if (ResponseCode_b64.empty()) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "Base64Encode fails." << std::endl;
        goto ON_tmain_ERROR;
    }

    std::cout << "License:" << std::endl;
    std::cout << ResponseCode_b64 << std::endl;

ON_tmain_ERROR:
    if (cipher)
        delete cipher;
    return 0;
}