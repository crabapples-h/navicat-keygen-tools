#include <vector>
#include <string>
#include <windows.h>

namespace Helper {

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
    
}
