#include <stddef.h>
#include <stdint.h>
#include <tchar.h>
#include <windows.h>
#include <ExceptionWin32.hpp>
#include <xstring.hpp>

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\Misc.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    template<typename __Type>
    static inline bool ProbeForRead(const void* p, void* out) {
        __try {
            *reinterpret_cast<__Type*>(out) = *reinterpret_cast<const __Type*>(p);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    //
    //  Print memory data in [lpMemBegin, lpMemEnd)
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must >= `from`
    //
    void PrintMemory(const void* lpMemBegin, const void* lpMemEnd, const void* lpBase) noexcept {
        auto pbBegin = reinterpret_cast<const uint8_t*>(lpMemBegin);
        auto pbEnd = reinterpret_cast<const uint8_t*>(lpMemEnd);
        auto pbBase = reinterpret_cast<const uint8_t*>(lpBase);

        if (pbBegin >= pbEnd)
            return;

        while (reinterpret_cast<uintptr_t>(pbBegin) % 16)
            pbBegin--;

        while (reinterpret_cast<uintptr_t>(pbEnd) % 16)
            pbEnd++;

        while (pbBegin < pbEnd) {
            uint16_t Values[16] = {};

            if (pbBase) {
                uintptr_t d = pbBegin >= lpBase ? pbBegin - pbBase : pbBase - pbBegin;
                if (pbBegin >= lpBase) {
                    _tprintf_s(TEXT("+0x%.*zx  "), static_cast<int>(2 * sizeof(void*)), d);
                } else {
                    _tprintf_s(TEXT("-0x%.*zx  "), static_cast<int>(2 * sizeof(void*)), d);
                }
            } else {
                _tprintf_s(TEXT("0x%.*zx  "), static_cast<int>(2 * sizeof(void*)), reinterpret_cast<uintptr_t>(pbBegin));
            }

            for (int i = 0; i < 16; ++i) {
                if (pbBegin + i < lpMemBegin || pbBegin + i >= lpMemEnd) {
                    _tprintf_s(TEXT("   "));
                    Values[i] = 0xfffe;
                } else if (ProbeForRead<uint8_t>(pbBegin + i, Values + i)) {
                    _tprintf_s(TEXT("%02x "), Values[i]);
                } else {
                    _tprintf_s(TEXT("?? "));
                    Values[i] = 0xffff;
                }
            }

            _tprintf_s(TEXT(" "));

            for (int i = 0; i < 16; ++i) {  // NOLINT
                if (0x20 <= Values[i] && Values[i] < 0x7f) {
                    _tprintf_s(TEXT("%c"), Values[i]);
                } else if (Values[i] == 0xfffe) {
                    _tprintf_s(TEXT(" "));
                } else {
                    _tprintf_s(TEXT("."));
                }
            }

            _tprintf_s(TEXT("\n"));

            pbBegin += 0x10;
        }
    }

    //
    //  Print memory data in [lpMem, lpMem + cbMem)
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must >= `from`
    //
    void PrintMemory(const void* lpMem, size_t cbMem, const void* lpBase) noexcept {
        PrintMemory(lpMem, reinterpret_cast<const uint8_t*>(lpMem) + cbMem, lpBase);
    }

    void PrintBytes(const void* lpMemBegin, const void* lpMemEnd) noexcept {
        auto pbMemBegin = reinterpret_cast<const uint8_t*>(lpMemBegin);
        auto pbMemEnd = reinterpret_cast<const uint8_t*>(lpMemEnd);

        if (pbMemBegin < pbMemEnd) {
            uint8_t v;

            if (ProbeForRead<uint8_t>(pbMemBegin, &v)) {
                _tprintf_s(TEXT("%.2x"), v);
            } else {
                _tprintf_s(TEXT("??"));
            }
            
            ++pbMemBegin;
        }

        while (pbMemBegin < pbMemEnd) {
            uint8_t v;

            if (ProbeForRead<uint8_t>(pbMemBegin, &v)) {
                _tprintf_s(TEXT(" %.2x"), v);
            } else {
                _tprintf_s(TEXT(" ??"));
            }

            ++pbMemBegin;
        }
    }

    void PrintBytes(const void* lpMem, size_t cbMem) noexcept {
        PrintBytes(lpMem, reinterpret_cast<const char*>(lpMem) + cbMem);
    }

    [[nodiscard]]
    bool IsValidDirectoryPath(PCTSTR lpszDirectoryPath) noexcept {
        DWORD Attribute = GetFileAttributes(lpszDirectoryPath);
        return Attribute != INVALID_FILE_ATTRIBUTES && (Attribute & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    [[nodiscard]]
    bool IsValidFilePath(PCTSTR lpszFilePath) noexcept {
        DWORD Attribute = GetFileAttributes(lpszFilePath);
        return Attribute != INVALID_FILE_ATTRIBUTES && (Attribute & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    [[nodiscard]]
    bool IsWineEnvironment() noexcept {
        static bool Checked = false;
        static bool IsWineEnv = false;

        if (Checked == false) {
            auto hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
            IsWineEnv = hNtdll && GetProcAddress(hNtdll, "wine_get_version") != nullptr;
            Checked = true;
        }

        return IsWineEnv;
    }

    std::xstring GetCurrentWorkingDirectory() {
        std::xstring CurrentDirectory;

        auto s = ::GetCurrentDirectory(0, NULL);
        if (s == 0) {
            throw Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("GetCurrentDirectory failed"));
        }

        CurrentDirectory.resize(static_cast<size_t>(s) - 1);

        s = ::GetCurrentDirectory(s, CurrentDirectory.data());
        if (s == 0) {
            throw Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("GetCurrentDirectory failed"));
        }

        return CurrentDirectory;
    }
}

