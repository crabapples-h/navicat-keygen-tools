#include "Exception.hpp"
#include "ExceptionGeneric.hpp"
#include "ResourceWrapper.hpp"
#include "ResourceTraitsOpenssl.hpp"
#include "RSACipher.hpp"
#include "Base64.hpp"
#include "SerialNumberGenerator.hpp"

#include <iostream>
#include <ctime>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

namespace nkg {

    void GenerateLicenseText(const RSACipher& Cipher, const SerialNumberGenerator& Generator) {
        std::string utf8username;
        std::string utf8organization;

        std::string b64RequestCode;
        std::vector<uint8_t> RequestCode;
        std::string utf8RequestInfo;
        std::string utf8ResponseInfo;
        std::vector<uint8_t> ResponseCode;
        std::string b64ResponseCode;

        std::cout << "[*] Your name: ";
        if (!std::getline(std::cin, utf8username)) {
            throw ARL::EOFError(__BASE_FILE__, __LINE__, "Abort.");
        }

        std::cout << "[*] Your organization: ";
        if (!std::getline(std::cin, utf8organization)) {
            throw ARL::EOFError(__BASE_FILE__, __LINE__, "Abort.");
        }

        std::cout << std::endl;

        std::cout << "[*] Input request code in Base64: (Double press ENTER to end)" << std::endl;
        while (true) {
            std::string temp;
            if (!std::getline(std::cin, temp)) {
                throw ARL::EOFError(__BASE_FILE__, __LINE__, "Abort.");
            }

            if (temp.empty()) {
                break;
            }

            b64RequestCode.append(temp);
        }

        RequestCode = base64_decode(b64RequestCode);
        if (RequestCode.size() != 256) {
            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Broken request code. %zu", RequestCode.size());
        }

        utf8RequestInfo.resize((Cipher.Bits() + 7) / 8);
        Cipher.Decrypt(RequestCode.data(), RequestCode.size(), utf8RequestInfo.data(), RSA_PKCS1_PADDING);
        while (utf8RequestInfo.back() == '\x00') {
            utf8RequestInfo.pop_back();
        }

        std::cout << "[*] Request Info:" << std::endl;
        std::cout << utf8RequestInfo << std::endl;
        std::cout << std::endl;

        rapidjson::Document json;
        rapidjson::Value N_Key;
        rapidjson::Value N_Value;
        rapidjson::Value O_Key;
        rapidjson::Value O_Value;
        rapidjson::Value T_Key;
        rapidjson::Value T_Value;
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

        //
        // Begin to parse
        //
        json.Parse(utf8RequestInfo.c_str());
        //
        // Remove "Platform" info
        //
        json.RemoveMember("P");
        //
        // Set "Name" info
        //
        N_Key.SetString("N", 1);
        N_Value.SetString(utf8username.c_str(), static_cast<rapidjson::SizeType>(utf8username.length()));
        //
        // Set "Organization" info
        //
        O_Key.SetString("O", 1);
        O_Value.SetString(utf8organization.c_str(), static_cast<rapidjson::SizeType>(utf8organization.length()));
        //
        // Set "Time" info
        //
        T_Key.SetString("T", 1);
        T_Value.SetUint(static_cast<unsigned int>(std::time(nullptr)));
        //
        // Add "Name", "Organization" and "Time"
        //
        json.AddMember(N_Key, N_Value, json.GetAllocator());
        json.AddMember(O_Key, O_Value, json.GetAllocator());
        json.AddMember(T_Key, T_Value, json.GetAllocator());

        json.Accept(writer);
        if (buffer.GetSize() > 240) {
            throw ARL::Exception(__BASE_FILE__, __LINE__, "Response info is too long.");
        }

        utf8ResponseInfo.assign(buffer.GetString(), buffer.GetSize());

        std::cout << "[*] Response Info:" << std::endl;
        std::cout << utf8ResponseInfo << std::endl;
        std::cout << std::endl;

        ResponseCode.resize((Cipher.Bits() + 7) / 8);
        Cipher.Encrypt<RSAKeyType::PrivateKey>(utf8ResponseInfo.data(), utf8ResponseInfo.size(), ResponseCode.data(), RSA_PKCS1_PADDING);

        b64ResponseCode = base64_encode(ResponseCode);

        std::cout << "[*] Activation Code:" << std::endl;
        std::cout << b64ResponseCode << std::endl;
        std::cout << std::endl;
    }

    void GenerateLicenseBinary(const RSACipher& Cipher, const SerialNumberGenerator& Generator) {
        ARL::ResourceWrapper LicenseFile{ ARL::ResourceTraits::OpensslBIO{} };

        std::string utf8SerialNumber = Generator.GetSerialNumberShort();
        std::string utf8username;
        std::string utf8organization;

        std::string utf8ResponseInfo;
        std::vector<uint8_t> ResponseCode;

        std::cout << "[*] Your name: ";
        if (!std::getline(std::cin, utf8username)) {
            throw ARL::EOFError(__BASE_FILE__, __LINE__, "Abort.");
        }

        std::cout << "[*] Your organization: ";
        if (!std::getline(std::cin, utf8organization)) {
            throw ARL::EOFError(__BASE_FILE__, __LINE__, "Abort.");
        }

        std::cout << std::endl;

        rapidjson::Document json;
        rapidjson::Value N_Key;
        rapidjson::Value N_Value;
        rapidjson::Value O_Key;
        rapidjson::Value O_Value;
        rapidjson::Value T_Key;
        rapidjson::Value T_Value;
        rapidjson::Value K_Key;
        rapidjson::Value K_Value;
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

        json.Parse("{}");
        K_Key.SetString("K", 1);
        K_Value.SetString(utf8SerialNumber.c_str(), static_cast<rapidjson::SizeType>(utf8SerialNumber.length()));
        N_Key.SetString("N", 1);
        N_Value.SetString(utf8username.c_str(), static_cast<rapidjson::SizeType>(utf8username.length()));
        O_Key.SetString("O", 1);
        O_Value.SetString(utf8organization.c_str(), static_cast<rapidjson::SizeType>(utf8organization.length()));
        T_Key.SetString("T", 1);
        T_Value.SetUint(static_cast<unsigned int>(std::time(nullptr)));

        json.AddMember(K_Key, K_Value, json.GetAllocator());
        json.AddMember(N_Key, N_Value, json.GetAllocator());
        json.AddMember(O_Key, O_Value, json.GetAllocator());
        json.AddMember(T_Key, T_Value, json.GetAllocator());

        json.Accept(writer);
        if (buffer.GetSize() > 240) {
            throw ARL::Exception(__BASE_FILE__, __LINE__, "Response info is too long.");
        }

        utf8ResponseInfo.assign(buffer.GetString(), buffer.GetSize());

        std::cout << "[*] Response Info:" << std::endl;
        std::cout << utf8ResponseInfo << std::endl;
        std::cout << std::endl;

        ResponseCode.resize((Cipher.Bits() + 7) / 8);
        Cipher.Encrypt<RSAKeyType::PrivateKey>(utf8ResponseInfo.data(), utf8ResponseInfo.size(), ResponseCode.data(), RSA_PKCS1_PADDING);

        LicenseFile.TakeOver(BIO_new_file("license_file", "w"));
        if (LicenseFile.IsValid() == false) {
            throw ARL::Exception(__BASE_FILE__, __LINE__, "BIO_new_file failed.");
        }

        if (BIO_write(LicenseFile, ResponseCode.data(), ResponseCode.size()) != ResponseCode.size()) {
            throw ARL::Exception(__BASE_FILE__, __LINE__, "BIO_write failed.");
        }

        std::cout << "[+] license_file has been generated." << std::endl;
    }
}

