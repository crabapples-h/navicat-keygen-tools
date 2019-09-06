#pragma once
#include <Exception.hpp>
#include <ExceptionWin32.hpp>
#include <xstring.hpp>
#include <bytearray.hpp>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32")

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-keygen\\Base64.hpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    std::xstring Base64Encode(const std::bytearray& Bytes) {
        if (Bytes.empty()) {
            return std::xstring();
        } else {
            DWORD cchBase64String = 0;
            std::xstring Base64String;

            auto bResult = CryptBinaryToString(
                Bytes.data(), 
                static_cast<DWORD>(Bytes.size()),
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                NULL,
                &cchBase64String
            );
            if (bResult == FALSE) {
                throw Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("CryptBinaryToString failed."));
            }

            Base64String.resize(cchBase64String - 1);

            bResult = CryptBinaryToString(
                Bytes.data(),
                static_cast<DWORD>(Bytes.size()),
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                Base64String.data(),
                &cchBase64String
            );
            if (bResult == FALSE) {
                throw Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("CryptBinaryToString failed."));
            }

            return Base64String;
        }
    }

    std::bytearray Base64Decode(const std::xstring& Base64String) {
        if (Base64String.empty()) {
            return std::bytearray();
        } else {
            DWORD cbBytes = 0;
            std::bytearray Bytes;

            auto bResult = CryptStringToBinary(
                Base64String.c_str(),
                NULL,
                CRYPT_STRING_BASE64,
                NULL,
                &cbBytes,
                NULL,
                NULL
            );
            if (bResult == FALSE) {
                throw Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("CryptStringToBinary failed."))
                    .AddHint(TEXT("Are you sure it is a Base64 string?"));
            }

            Bytes.resize(cbBytes);

            bResult = CryptStringToBinary(
                Base64String.c_str(),
                NULL,
                CRYPT_STRING_BASE64,
                Bytes.data(),
                &cbBytes,
                NULL,
                NULL
            );

            if (bResult == FALSE) {
                throw Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("CryptStringToBinary failed."));
            }

            return Bytes;
        }
    }
}
