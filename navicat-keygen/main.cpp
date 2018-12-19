#include <iostream>
#include "Helper.hpp"
#include "RSACipher.hpp"
#include "DESCipher.hpp"
#include "NavicatKeygen.hpp"

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

void help() {
    std::cout << "Usage:" << std::endl
              << "    ./navicat-keygen <RSA-2048 PrivateKey(PEM file)>" << std::endl
              << std::endl;
}

int main(int argc, char* argv[], char* envp[]) {
    if (argc != 2) {
        help();
        return 0;
    }

    Helper::ResourceGuard<RSACipher> cipher(RSACipher::Create());
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

    if (cipher.ptr == nullptr) {
        std::cout << "@Function: " << __FUNCTION__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: Failed to create RSACipher." << std::endl;
        return 0;
    }

    if (!cipher.ptr->ImportKeyFromFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::PEM>(argv[1])) {
        std::cout << "@Function: " << __FUNCTION__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: Failed to load RSA-2048 key." << std::endl;
        return 0;
    }

    keygen.SetProductSignature(NavicatKeygen::Product::Premium);

    std::cout
            << "Which is your Navicat Premium language?" << std::endl
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

    {
        int num;
        if (!Helper::ReadNumber<0, 10>(num, "(Input index)> ", "Invalid index."))
            return 0;
        keygen.SetLanguageSignature(static_cast<NavicatKeygen::Language>(num));

        if (!Helper::ReadNumber<0, 15>(num, "(Input major version number, range: 0 ~ 15, default: 12)> ", "Invalid number."))
            return 0;
        keygen.SetVersion(static_cast<uint8_t>(num));
    }

    //
    //  Generate snKey
    //
    keygen.Generate();
    std::cout << std::endl;
    std::cout << "Serial number:" << std::endl;
    std::cout << keygen.GetFormatedKey() << std::endl;
    std::cout << std::endl;

    //
    //  Get user name
    //
    std::cout << "Your name: ";
    if (!std::getline(std::cin, username))
        return 0;

    //
    //  Get organization name
    //
    std::cout << "Your organization: ";
    if (!std::getline(std::cin, organization))
        return 0;

    std::cout << std::endl;

    //
    //  Get request code in base64
    //
    std::cout << "Input request code (in Base64), input empty line to end:" << std::endl;
    while (true) {
        std::string temp;
        if (!std::getline(std::cin, temp))
            return 0;

        if (temp.empty())
            break;

        RequestCode_b64 += temp;
    }

    //
    //  Get request code in raw bytes
    //
    try {
        RequestCode = Helper::base64_decode(RequestCode_b64);
    } catch(...) {
        std::cout << "@Function: " << __FUNCTION__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: Helper::base64_decode fails." << std::endl;
        return 0;
    }

    //
    //  Decrypt to get request info
    //
    if (!cipher.ptr->Decrypt(RequestCode.data(), static_cast<int>(RequestCode.size()), RequestInfo, RSA_PKCS1_PADDING)) {
        std::cout << "@Function: " << __FUNCTION__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: Decrypt<RSACipher::KeyType::PrivateKey> fails." << std::endl;
        return 0;
    }

    //
    //  print out request info
    //
    std::cout << "Request Info:" << std::endl;
    std::cout << RequestInfo << std::endl;
    std::cout << std::endl;

    //
    //  Generate response info
    //
    json.Parse(RequestInfo);
    json.RemoveMember("P");     // remove Platform info

    N_Key.SetString("N", 1);
    N_Value.SetString(username.c_str(), static_cast<rapidjson::SizeType>(username.length()));
    O_Key.SetString("O", 1);
    O_Value.SetString(organization.c_str(), static_cast<rapidjson::SizeType>(organization.length()));
    T_Key.SetString("T", 1);
    T_Value.SetUint(static_cast<unsigned>(std::time(nullptr)));

    json.AddMember(N_Key, N_Value, json.GetAllocator());
    json.AddMember(O_Key, O_Value, json.GetAllocator());
    json.AddMember(T_Key, T_Value, json.GetAllocator());

    json.Accept(writer);

    if (buffer.GetSize() > 240) {
        std::cout << "@Function: " << __FUNCTION__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: Response info is too long." << std::endl;
        return 0;
    }

    //
    //  print out response info
    //
    memcpy(ResponseInfo, buffer.GetString(), buffer.GetSize());
    std::cout << "Response Info:" << std::endl;
    std::cout << ResponseInfo << std::endl;
    std::cout << std::endl;

    //
    //  encrypt response info
    //
    ResponseCode.resize(256);
    if (!cipher.ptr->Encrypt<RSACipher::KeyType::PrivateKey>(ResponseInfo,
                                                             static_cast<int>(strlen(ResponseInfo)),
                                                             ResponseCode.data(),
                                                             RSA_PKCS1_PADDING)) {
        std::cout << "@Function: " << __FUNCTION__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: Encrypt<RSACipher::KeyType::PrivateKey> fails." << std::endl;
        return 0;
    }

    //
    //  Encode encrypted response info in base64 format
    //
    try {
        ResponseCode_b64 = Helper::base64_encode(ResponseCode);
    } catch(...) {
        std::cout << "@Function: " << __FUNCTION__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: Helper::base64_encode fails." << std::endl;
        return 0;
    }

    //
    //  print out activation code
    //
    std::cout << "License:" << std::endl;
    std::cout << ResponseCode_b64 << std::endl;

    return 0;
}

