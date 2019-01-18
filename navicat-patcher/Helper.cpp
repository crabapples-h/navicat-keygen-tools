#include "Helper.hpp"
#include <tchar.h>
#include "ExceptionSystem.hpp"
#include "ResourceGuard.hpp"

#undef __BASE_FILE__
#define __BASE_FILE__ "Helper.cpp"

namespace Helper {

    static Navicat11Crypto NavicatCipher("23970790", 8);

    std::string ConvertToUTF8(PCSTR From, DWORD CodePage) {
        std::string result;
        int RequiredLength = 0;
        ResourceGuard<CppDynamicArrayTraits<WCHAR>> pszUnicodeString;

        RequiredLength = MultiByteToWideChar(CP_ACP, 
                                             NULL, 
                                             From, 
                                             -1, 
                                             nullptr, 
                                             0);
        if (RequiredLength == 0)
            throw SystemError(__BASE_FILE__, __LINE__, GetLastError(), 
                              "MultiByteToWideChar fails.");

        pszUnicodeString.TakeHoldOf(new WCHAR[RequiredLength]());

        if (!MultiByteToWideChar(CP_ACP, 
                                 NULL, 
                                 From, 
                                 -1, 
                                 pszUnicodeString, 
                                 RequiredLength))
            throw SystemError(__BASE_FILE__, __LINE__, GetLastError(),
                              "MultiByteToWideChar fails.");

        RequiredLength = WideCharToMultiByte(CP_UTF8, 
                                             NULL, 
                                             pszUnicodeString, 
                                             -1, 
                                             nullptr, 
                                             0, 
                                             nullptr, 
                                             nullptr);
        if (RequiredLength == 0)
            throw SystemError(__BASE_FILE__, __LINE__, GetLastError(),
                              "WideCharToMultiByte fails.");

        result.resize(RequiredLength);

        if (!WideCharToMultiByte(CP_UTF8, 
                                 NULL, 
                                 pszUnicodeString, 
                                 -1, 
                                 result.data(), 
                                 RequiredLength, 
                                 nullptr, 
                                 nullptr))
            throw SystemError(__BASE_FILE__, __LINE__, GetLastError(),
                              "WideCharToMultiByte fails.");

        while (result.back() == 0)
            result.pop_back();

        return result;
    }

    std::string ConvertToUTF8(PCWSTR From) {
        std::string result;
        int RequiredLength = 0;

        RequiredLength = WideCharToMultiByte(CP_UTF8, 
                                             NULL, 
                                             From, 
                                             -1, 
                                             nullptr, 
                                             0, 
                                             nullptr, 
                                             nullptr);
        if (RequiredLength == 0)
            throw SystemError(__BASE_FILE__, __LINE__, GetLastError(),
                              "WideCharToMultiByte fails.");

        result.resize(RequiredLength);

        if (!WideCharToMultiByte(CP_UTF8, 
                                 NULL, 
                                 From, 
                                 -1, 
                                 result.data(), 
                                 RequiredLength, 
                                 nullptr, 
                                 nullptr))
            throw SystemError(__BASE_FILE__, __LINE__, GetLastError(),
                              "WideCharToMultiByte fails.");

        while (result.back() == 0)
            result.pop_back();

        return result;
    }

    //
    //  read byte(s) at address `p` as _Type to `out`
    //  succeed if return true, otherwise return false
    //
    template<typename _Type>
    static __forceinline bool ProbeForRead(const void* p, void* out) {
        __try {
            *reinterpret_cast<_Type*>(out) = *reinterpret_cast<const _Type*>(p);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    //
    //  Print memory data in [from, to) at least
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must <= `from`
    //  
    void PrintMemory(const void* from, const void* to, const void* base) {
        const uint8_t* start = reinterpret_cast<const uint8_t*>(from);
        const uint8_t* end = reinterpret_cast<const uint8_t*>(to);
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

    void PrintSomeBytes(const void* p, size_t s) {
        const uint8_t* byte_ptr = reinterpret_cast<const uint8_t*>(p);

        if (s == 0)
            return;

        if (s == 1) {
            _tprintf_s(TEXT("%02X"), byte_ptr[0]);
            return;
        }

        s -= 1;
        for (size_t i = 0; i < s; ++i)
            _tprintf_s(TEXT("%02X "), byte_ptr[i]);

        _tprintf_s(TEXT("%02X"), byte_ptr[s]);
    }

    bool IsPrintable(const uint8_t* p, size_t s) {
        for (size_t i = 0; i < s; ++i)
            if (isprint(p[i]) == false)
                return false;
        return true;
    }
}
