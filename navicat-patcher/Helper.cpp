#include "def.hpp"
#include "NavicatCrypto.hpp"

namespace Helper {

    static Navicat11Crypto NavicatCipher("23970790", 8);

    std::string EncryptPublicKey(const std::string& PublicKeyString) {
        return NavicatCipher.EncryptString(PublicKeyString.c_str(), 
                                           PublicKeyString.length());
    }

    bool ConvertToUTF8(LPCSTR from, std::string& to) {
        bool bSuccess = false;
        int RequireLength = 0;
        LPWSTR lpUnicodeString = nullptr;

        RequireLength = MultiByteToWideChar(CP_ACP, NULL, from, -1, nullptr, 0);
        if (RequireLength == 0)
            goto ON_ConvertToUTF8_0_ERROR;

        lpUnicodeString = reinterpret_cast<LPWSTR>(HeapAlloc(GetProcessHeap(),
                                                             HEAP_ZERO_MEMORY,
                                                             RequireLength * sizeof(WCHAR)));
        if (lpUnicodeString == nullptr)
            goto ON_ConvertToUTF8_0_ERROR;

        if (!MultiByteToWideChar(CP_ACP, NULL, from, -1, lpUnicodeString, RequireLength))
            goto ON_ConvertToUTF8_0_ERROR;

        RequireLength = WideCharToMultiByte(CP_UTF8, NULL, lpUnicodeString, -1, nullptr, 0, nullptr, nullptr);
        if (RequireLength == 0)
            goto ON_ConvertToUTF8_0_ERROR;

        to.resize(RequireLength);

        if (!WideCharToMultiByte(CP_UTF8, NULL, lpUnicodeString, -1, to.data(), RequireLength, nullptr, nullptr))
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
        int RequireLength = 0;

        RequireLength = WideCharToMultiByte(CP_UTF8, NULL, from, -1, nullptr, 0, nullptr, nullptr);
        if (RequireLength == 0)
            goto ON_ConvertToUTF8_1_ERROR;

        to.resize(RequireLength);
        if (!WideCharToMultiByte(CP_UTF8, NULL, from, -1, to.data(), RequireLength, nullptr, nullptr))
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
        if (bSuccess)
            str = temp;

        return bSuccess;
    }

    void ErrorReport(LPCTSTR at, UINT line, LPCTSTR msg) {
        _tprintf_s(TEXT("@%s LINE: %u\n"), at, line);
        _tprintf_s(TEXT("%s\n"), msg);
    }

    void ErrorReport(LPCTSTR at, UINT line, LPCTSTR msg, DWORD err_code) {
        _tprintf_s(TEXT("@%s LINE: %u\n"), at, line);
        _tprintf_s(TEXT("%s CODE: 0x%08X\n"), msg, err_code);
    }

    template<typename _Type>
    static __forceinline bool ProbeForRead(const void* p, void* out) {
        __try {
            *reinterpret_cast<_Type*>(out) = *reinterpret_cast<const _Type*>(p);
            return true;
        } __except (1) {
            return false;
        }
    }

    void PrintMemory(const void* a, const void* b, const void* base) {
        const uint8_t* start = reinterpret_cast<const uint8_t*>(a);
        const uint8_t* end = reinterpret_cast<const uint8_t*>(b);
        const uint8_t* base_ptr = reinterpret_cast<const uint8_t*>(base);

        if (start >= end)
            return;

        while (reinterpret_cast<uintptr_t>(start) % 16) 
            start--;

        while (reinterpret_cast<uintptr_t>(start) % 16) 
            end++;

        while (start < end) {
            uint16_t value[16] = {};

            if (base_ptr) 
                _tprintf(TEXT("+0x%p  "), reinterpret_cast<const void*>(start - base_ptr));
            else
                _tprintf(TEXT("0x%p  "), start);

            for (int i = 0; i < 16; ++i) {
                if (ProbeForRead<uint8_t>(start + i, value + i)) {
                    _tprintf(TEXT("%02x "), value[i]);
                } else {
                    value[i] = -1;
                    _tprintf(TEXT("?? "));
                }
            }

            _tprintf(TEXT(" "));

            for (int i = 0; i < 16; ++i) {
                if (value[i] < 0x20) {
                    _tprintf(TEXT("."));
                } else if (value[i] > 0x7e) {
                    _tprintf(TEXT("."));
                } else {
                    _tprintf(TEXT("%c"), value[i]);
                }
            }

            _tprintf(TEXT("\n"));

            start += 0x10;
        }
    }

}