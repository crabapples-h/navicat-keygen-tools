#include <iostream>
#include <ctime>
#include <windows.h>

#include "RSACipher.hpp"
#include "NavicatKeygen.hpp"

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

namespace Helper {
    bool ConvertToUTF8(LPCSTR from, std::string& to);
    bool ConvertToUTF8(LPCWSTR from, std::string& to);
    bool ConvertToUTF8(std::string& str);

    std::string Base64Encode(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> Base64Decode(std::string& str);

    template<int min_num, int max_num>
    bool ReadNumber(int& num, const char* msg, const char* err_msg) {
        int temp;
        std::string input;
        while (true) {
            std::cout << msg;
            if (!std::getline(std::cin, input))
                return false;

            try {
                temp = std::stoi(input, nullptr, 0);
                if (min_num <= temp && temp <= max_num) {
                    num = temp;
                    return true;
                } else {
                    throw std::invalid_argument("Invalid number");
                }
            } catch (...) {
                std::cout << err_msg << std::endl;
            }
        }
    }
}

#define MODE_SIMPLE     1
#define MODE_ADVANCED   2
#define FLAG_BIN        1
#define FLAG_TEXT       2
void Process(RSACipher* cipher, int mode, int flag) {
    std::string input;
    int num;

    NavicatKeygen::Product product;
    NavicatKeygen::Language language;
    uint8_t product0;
    uint8_t language0, language1;
    uint8_t version;
    NavicatKeygen keygen;
    std::string username;
    std::string organization;

    std::string RequestCode_b64;
    std::vector<uint8_t> RequestCode;
    char RequestInfo[256] = {};
    char ResponseInfo[256] = {};
    std::vector<uint8_t> ResponseCode;
    std::string ResponseCode_b64;

    rapidjson::Document json;
    rapidjson::Value N_Key;
    rapidjson::Value N_Value;
    rapidjson::Value O_Key;
    rapidjson::Value O_Value;
    rapidjson::Value T_Key;
    rapidjson::Value T_Value;
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

    if (mode == MODE_SIMPLE) {
        std::cout << "Select Navicat product:" << std::endl
            << "0. DataModeler" << std::endl
            << "1. Premium" << std::endl
            << "2. MySQL" << std::endl
            << "3. PostgreSQL" << std::endl
            << "4. Oracle" << std::endl
            << "5. SQLServer" << std::endl
            << "6. SQLite" << std::endl
            << "7. MariaDB" << std::endl
            << "8. MongoDB" << std::endl
            << "9. ReportViewer" << std::endl
            << std::endl;

        if (!Helper::ReadNumber<0, 9>(num,
                                      "(Input index)> ",
                                      "Invalid index.")) {
            return;
        }
        product = static_cast<NavicatKeygen::Product>(num);

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

        if (!Helper::ReadNumber<0, 10>(num,
                                       "(Input index)> ",
                                       "Invalid index.")) {
            return;
        }
        language = static_cast<NavicatKeygen::Language>(num);

        std::cout << std::endl;

        keygen.SetProductSignature(product);
        keygen.SetLanguageSignature(language);
    }
    
    if (mode == MODE_ADVANCED) {
        
        if (!Helper::ReadNumber<0, 255>(num,
                                        "(Navicat Product ID, 0x00 ~ 0xFF)> ",
                                        "Invalid number.")) {
            return;
        }
        product0 = static_cast<uint8_t>(num);

        if (!Helper::ReadNumber<0, 255>(num,
                                        "(Navicat Language Signature 0, 0x00 ~ 0xFF)> ",
                                        "Invalid number.")) {
            return;
        }
        language0 = static_cast<uint8_t>(num);

        if (!Helper::ReadNumber<0, 255>(num,
                                        "(Navicat Language Signature 1, 0x00 ~ 0xFF)> ",
                                        "Invalid number.")) {
            return;
        }
        language1 = static_cast<uint8_t>(num);

        keygen.SetProductSignature(product0);
        keygen.SetLanguageSignature(language0, language1);
    }
    
    if (!Helper::ReadNumber<0, 16 - 1>(num,
                                       "(Input major version number, range: 0 ~ 15, default: 12)> ",
                                       "Invalid number.")) {
        return;
    }
    version = static_cast<uint8_t>(num);
    keygen.SetVersion(version);

    keygen.Generate();
    std::cout << std::endl;
    std::cout << "Serial number:" << std::endl;
    std::cout << keygen.GetFormatedKey() << std::endl;
    std::cout << std::endl;

    std::cout << "Your name: ";
    if (!std::getline(std::cin, username))
        return;
    if (!Helper::ConvertToUTF8(username)) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: ConvertToUTF8 fails." << std::endl;
        return;
    }

    std::cout << "Your organization: ";
    if (!std::getline(std::cin, organization))
        return;
    if (!Helper::ConvertToUTF8(organization)) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: ConvertToUTF8 fails." << std::endl;
        return;
    }

    std::cout << std::endl;

    if (flag == FLAG_TEXT) {
        std::cout << "Input request code (in Base64), input empty line to end:" << std::endl;
        while (true) {
            std::string temp;
            if (!std::getline(std::cin, temp))
                return;

            if (temp.empty())
                break;

            RequestCode_b64 += temp;
        }

        RequestCode = Helper::Base64Decode(RequestCode_b64);
        if (RequestCode.empty()) {
            std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
            std::cout << "ERROR: Base64Decode fails." << std::endl;
            return;
        }

        if (!cipher->Decrypt(RequestCode.data(),
                             RequestCode.size(),
                             RequestInfo,
                             RSA_PKCS1_PADDING)) {
            std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
            std::cout << "ERROR: Decrypt<RSACipher::KeyType::PrivateKey> fails." << std::endl;
            return;
        }

        std::cout << "Request Info:" << std::endl;
        std::cout << RequestInfo << std::endl;
        std::cout << std::endl;

        json.Parse(RequestInfo);
        json.RemoveMember("P");     // remove Platform info


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
            std::cout << "ERROR: Response info is too long." << std::endl;
            return;
        }

        memcpy(ResponseInfo, buffer.GetString(), buffer.GetSize());

        std::cout << "Response Info:" << std::endl;
        std::cout << ResponseInfo << std::endl;
        std::cout << std::endl;

        ResponseCode.resize(256);

        if (!cipher->Encrypt<RSACipher::KeyType::PrivateKey>(ResponseInfo,
                                                             strlen(ResponseInfo),
                                                             ResponseCode.data(),
                                                             RSA_PKCS1_PADDING)) {
            std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
            std::cout << "ERROR: Encrypt<RSACipher::KeyType::PrivateKey> fails." << std::endl;
            return;
        }

        ResponseCode_b64 = Helper::Base64Encode(ResponseCode);
        if (ResponseCode_b64.empty()) {
            std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
            std::cout << "Base64Encode fails." << std::endl;
            return;
        }

        std::cout << "License:" << std::endl;
        std::cout << ResponseCode_b64 << std::endl;
    }

    if (flag == FLAG_BIN) {
        rapidjson::Value K_Key;
        rapidjson::Value K_Value;
        HANDLE hFile = INVALID_HANDLE_VALUE;
        DWORD NumberOfBytesWritten;

        json.Parse("{}");

        K_Key.SetString("K", 1);
        K_Value.SetString(keygen.GetKey().c_str(), keygen.GetKey().size());
        N_Key.SetString("N", 1);
        N_Value.SetString(username.c_str(), username.length());
        O_Key.SetString("O", 1);
        O_Value.SetString(organization.c_str(), organization.length());
        T_Key.SetString("T", 1);
        T_Value.SetUint(std::time(nullptr));

        json.AddMember(K_Key, K_Value, json.GetAllocator());
        json.AddMember(N_Key, N_Value, json.GetAllocator());
        json.AddMember(O_Key, O_Value, json.GetAllocator());
        json.AddMember(T_Key, T_Value, json.GetAllocator());

        json.Accept(writer);
        if (buffer.GetSize() > 240) {
            std::cout << "ERROR: Response info is too long." << std::endl;
            return;
        }

        memcpy(ResponseInfo, buffer.GetString(), buffer.GetSize());

        std::cout << "Response Info:" << std::endl;
        std::cout << ResponseInfo << std::endl;
        std::cout << std::endl;

        ResponseCode.resize(256);

        if (!cipher->Encrypt<RSACipher::KeyType::PrivateKey>(ResponseInfo,
                                                             strlen(ResponseInfo),
                                                             ResponseCode.data(),
                                                             RSA_PKCS1_PADDING)) {
            std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
            std::cout << "ERROR: Encrypt<RSACipher::KeyType::PrivateKey> fails." << std::endl;
            return;
        }

        hFile = CreateFile(TEXT("license_file"),
                           GENERIC_READ | GENERIC_WRITE,
                           0,
                           nullptr,
                           CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD dwLastError = GetLastError();
            std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
            std::cout << "ERROR: CreateFile fails. CODE: " << dwLastError << std::endl;
            return;
        }

        if (!WriteFile(hFile, ResponseCode.data(), ResponseCode.size(), &NumberOfBytesWritten, nullptr)) {
            DWORD dwLastError = GetLastError();
            std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
            std::cout << "ERROR: WriteFile fails. CODE: " << dwLastError << std::endl;
            CloseHandle(hFile);
            return;
        }

        CloseHandle(hFile);

        std::cout << "license_file has been generated." << std::endl;
    }
    
}
