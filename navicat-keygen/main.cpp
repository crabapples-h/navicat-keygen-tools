#include <stddef.h> // NOLINT
#include <stdint.h> // NOLINT
#include <iostream>
#include <vector>
#include <string>

#include "../common/RSACipher.hpp"
#include "NavicatKeygen.hpp"

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

template<int min_num, int max_num>
bool read_int(int& num, const char* prompt, const char* err_msg) {
    int temp;
    std::string input;

    while (true) {
        std::cout << prompt;
        if (!std::getline(std::cin, input))
            return false;

        try {
            temp = std::stoi(input, nullptr, 0);
            if (min_num <= temp && temp <= max_num) {
                num = temp;
                return true;
            } else {
                throw std::invalid_argument(err_msg);
            }
        } catch (...) {
            std::cout << err_msg << std::endl;
        }
    }
}

std::string base64_encode(const std::vector<uint8_t>& bindata);
std::vector<uint8_t> base64_decode(const std::string& ascdata);

void Help() {
    std::cout << "***************************************************"                                      << std::endl;
    std::cout << "*       Navicat Keygen by @DoubleLabyrinth        *"                                      << std::endl;
    std::cout << "*                  Version: 4.0                   *"                                      << std::endl;
    std::cout << "***************************************************"                                      << std::endl;
    std::cout <<                                                                                               std::endl;
    std::cout << "Usage:"                                                                                   << std::endl;
    std::cout << "    navicat-keygen <RSA-2048 Private Key File>"                                           << std::endl;
    std::cout <<                                                                                               std::endl;
    std::cout << "        <RSA-2048 Private Key File>    Path to a PEM-format RSA-2048 private key file."   << std::endl;
    std::cout << "                                       This parameter must be specified."                 << std::endl;
    std::cout <<                                                                                               std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        Help();
        return -1;
    } else {
        try {
            std::cout << "***************************************************"  << std::endl;
            std::cout << "*       Navicat Keygen by @DoubleLabyrinth        *"  << std::endl;
            std::cout << "*                  Version: 4.0                   *"  << std::endl;
            std::cout << "***************************************************"  << std::endl;
            std::cout << std::endl;

            RSACipher RsaCipher;

            int select_num;

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

            RsaCipher.ImportKeyFromFile<RSAKeyType::PrivateKey, RSAKeyFormat::PEM>(argv[1]);
            if (RsaCipher.Bits() != 2048) {
                // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                throw nkg::Exception(__FILE__, __LINE__, "Not RSA-2048 private key file.");
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
            if (read_int<0, 10>(select_num, "(Input index)> ", "Invalid index.")) {
                keygen.SetLanguageSignature(static_cast<NavicatKeygen::Language>(select_num));
            } else {
                return -1;
            }

            std::cout << std::endl;

            if (read_int<0, 15>(select_num, "(Input major version number, range: 0 ~ 15, default: 12)> ", "Invalid number.")) {
                keygen.SetVersion(static_cast<uint8_t>(select_num));
            } else {
                return -1;
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
            if (!std::getline(std::cin, username)) {
                return -1;
            }

            //
            //  Get organization name
            //
            std::cout << "Your organization: ";
            if (!std::getline(std::cin, organization)) {
                return -1;
            }

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
            RequestCode = base64_decode(RequestCode_b64);
            if (RequestCode.size() > ((RsaCipher.Bits() + 7) / 8)) {
                // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                throw nkg::Exception(__FILE__, __LINE__, "Request code is too long.");
            }

            //
            //  Decrypt to get request info
            //
            RsaCipher.Decrypt(RequestCode.data(), static_cast<int>(RequestCode.size()), RequestInfo, RSA_PKCS1_PADDING);

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
                // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                throw nkg::Exception(__FILE__, __LINE__, "Response info is too long.");
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
            ResponseCode.resize((RsaCipher.Bits() + 7) / 8);
            RsaCipher.Encrypt<RSAKeyType::PrivateKey>(ResponseInfo, static_cast<int>(strlen(ResponseInfo)), ResponseCode.data(), RSA_PKCS1_PADDING);

            //
            //  encode encrypted response info in base64 format
            //
            ResponseCode_b64 = base64_encode(ResponseCode);

            //
            //  print out activation code
            //
            std::cout << "License:" << std::endl;
            std::cout << ResponseCode_b64 << std::endl;

            return 0;
        } catch (nkg::Exception& e) {
            std::cout << "[-] " << e.File() << ":" << e.Line() << " ->" << std::endl;
            std::cout << "    " << e.Message() << std::endl;
            if (e.HasErrorCode()) {
                std::cout << "    " << e.ErrorString() << std::endl;
            }
            return -1;
        }
    }
}

