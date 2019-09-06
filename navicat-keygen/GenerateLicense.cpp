#include <ExceptionUser.hpp>
#include <ResourceOwned.hpp>
#include <ResourceTraitsWin32.hpp>

#include <xstring.hpp>
#include <bytearray.hpp>
#include <RSACipher.hpp>
#include "Base64.hpp"
#include "SerialNumberGenerator.hpp"

#include <iostream>
#include <ctime>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-keygen\\GenerateLicense.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace std {
#if defined(_UNICODE) || defined(UNICODE)
    static auto & xcin = wcin;
    static auto& xcout = wcout;
    static auto& xcerr = wcerr;
#else
    static auto& xcin = cin;
    static auto& xcout = cout;
    static auto& xcerr = cerr;
#endif
}

namespace nkg {

    void GenerateLicenseText(const RSACipher& Cipher, const SerialNumberGenerator& Generator) {
        std::xstring username;
        std::xstring organization;
        std::string utf8username;
        std::string utf8organization;

        std::xstring b64RequestCode;
        std::bytearray RequestCode;
        std::string utf8RequestInfo;
        std::string utf8ResponseInfo;
        std::bytearray ResponseCode;
        std::xstring b64ResponseCode;

        std::xcout << TEXT("[*] Your name: ");
        if (!std::getline(std::xcin, username)) {
            throw UserAbortionError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Abort."));
        } else {
            utf8username = username.explicit_string(CP_UTF8);
        }

        std::xcout << TEXT("[*] Your organization: ");
        if (!std::getline(std::xcin, organization)) {
            throw UserAbortionError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Abort."));
        } else {
            utf8organization = organization.explicit_string(CP_UTF8);
        }

        std::xcout << TEXT("[*] Input request code in Base64: (Input empty line to end)") << std::endl;
        while (true) {
            std::xstring temp;
            if (!std::getline(std::xcin, temp)) {
                throw UserAbortionError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Abort."));
            }

            if (temp.empty()) {
                break;
            }

            b64RequestCode.append(temp);
        }

        RequestCode = Base64Decode(b64RequestCode);

        utf8RequestInfo.resize((Cipher.Bits() + 7) / 8);
        Cipher.Decrypt(RequestCode.data(), RequestCode.size(), utf8RequestInfo.data(), RSA_PKCS1_PADDING);
        while (utf8RequestInfo.back() == '\x00') {
            utf8RequestInfo.pop_back();
        }

        std::xcout << TEXT("[*] Request Info:") << std::endl;
        std::xcout << std::xstring(std::xstring_extension{}, utf8RequestInfo, CP_UTF8) << std::endl;
        std::xcout << std::endl;

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
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Response info is too long."));
        }

        utf8ResponseInfo.assign(buffer.GetString(), buffer.GetSize());

        std::xcout << TEXT("[*] Response Info:") << std::endl;
        std::xcout << std::xstring(std::xstring_extension{}, utf8ResponseInfo, CP_UTF8) << std::endl;
        std::xcout << std::endl;

        ResponseCode.resize((Cipher.Bits() + 7) / 8);
        Cipher.Encrypt<RSAKeyType::PrivateKey>(utf8ResponseInfo.data(), utf8ResponseInfo.size(), ResponseCode.data(), RSA_PKCS1_PADDING);
        b64ResponseCode = Base64Encode(ResponseCode);

        std::xcout << TEXT("[*] Activation Code:") << std::endl;
        std::xcout << b64ResponseCode << std::endl;
        std::xcout << std::endl;
    }

    void GenerateLicenseBinary(const RSACipher& Cipher, const SerialNumberGenerator& Generator) {
        ResourceOwned hLicenseFile(FileHandleTraits{});

        std::string utf8SerialNumber = Generator.GetSerialNumberShort().explicit_string(CP_UTF8);

        std::xstring username;
        std::xstring organization;
        std::string utf8username;
        std::string utf8organization;

        std::string utf8ResponseInfo;
        std::bytearray ResponseCode;

        std::xcout << TEXT("[*] Your name: ");
        if (!std::getline(std::xcin, username)) {
            throw UserAbortionError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Abort."));
        } else {
            utf8username = username.explicit_string(CP_UTF8);
        }

        std::xcout << TEXT("[*] Your organization: ");
        if (!std::getline(std::xcin, organization)) {
            throw UserAbortionError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Abort."));
        } else {
            utf8organization = organization.explicit_string(CP_UTF8);
        }

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
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Response info is too long."));
        }

        utf8ResponseInfo.assign(buffer.GetString(), buffer.GetSize());

        std::xcout << TEXT("[*] Response Info:") << std::endl;
        std::xcout << std::xstring(std::xstring_extension{}, utf8ResponseInfo, CP_UTF8) << std::endl;
        std::xcout << std::endl;

        ResponseCode.resize((Cipher.Bits() + 7) / 8);
        Cipher.Encrypt<RSAKeyType::PrivateKey>(utf8ResponseInfo.data(), utf8ResponseInfo.size(), ResponseCode.data(), RSA_PKCS1_PADDING);

        hLicenseFile.TakeOver(
            CreateFile(
                TEXT("license_file"),
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            )
        );
        if (hLicenseFile.IsValid() == false) {
            throw Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("CreateFile failed."));
        }

        DWORD NumberOfBytesWritten;
        if (!WriteFile(hLicenseFile, ResponseCode.data(), static_cast<DWORD>(ResponseCode.size()), &NumberOfBytesWritten, NULL)) {
            throw Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("WriteFile failed."));
        }

        std::xcout << TEXT("[+] license_file has been generated.") << std::endl;


    }
}
