#pragma once
#include <stddef.h>
#include <tchar.h>
#include <windows.h>
#include <type_traits>
#include <xstring.hpp>

#define LOG_SUCCESS(tab, fmt, ...) tab ? _tprintf_s(TEXT("%*c[+] " fmt "\n"), tab, ' ', __VA_ARGS__) : _tprintf_s(TEXT("[+] " fmt "\n"), __VA_ARGS__)
#define LOG_FAILURE(tab, fmt, ...) tab ? _tprintf_s(TEXT("%*c[-] " fmt "\n"), tab, ' ', __VA_ARGS__) : _tprintf_s(TEXT("[-] " fmt "\n"), __VA_ARGS__)
#define LOG_HINT(tab, fmt, ...) tab ? _tprintf_s(TEXT("%*c[*] " fmt "\n"), tab, ' ', __VA_ARGS__) : _tprintf_s(TEXT("[*] " fmt "\n"), __VA_ARGS__)
#define LOG_SELECT(tab, fmt, ...) tab ? _tprintf_s(TEXT("%*c[?] " fmt " "), tab, ' ', __VA_ARGS__) : _tprintf_s(TEXT("[?] " fmt " "), __VA_ARGS__)

namespace nkg {

    template<size_t __Len>
    constexpr size_t literal_length(const char (&)[__Len]) noexcept {
        return __Len - 1;
    }

    template<typename __PtrType1, typename __PtrType2>
    constexpr auto address_delta(__PtrType1 p1, __PtrType2 p2) noexcept {
        static_assert(std::is_pointer_v<__PtrType1>);
        static_assert(std::is_pointer_v<__PtrType2>);
        return reinterpret_cast<const volatile char*>(p1) - reinterpret_cast<const volatile char*>(p2);
    }

    template<typename __PtrType>
    constexpr __PtrType address_offset(__PtrType p, decltype(static_cast<char*>(nullptr) - static_cast<char*>(nullptr)) offset) noexcept {
        static_assert(std::is_pointer_v<__PtrType>);
        return reinterpret_cast<__PtrType>(
            const_cast<char*>(reinterpret_cast<const volatile char*>(p)) + offset
        );
    }

    template<typename __ReturnType, typename __PtrType>
    constexpr __ReturnType address_offset_cast(__PtrType p, decltype(static_cast<char*>(nullptr) - static_cast<char*>(nullptr)) offset) noexcept {
        static_assert(std::is_pointer_v<__ReturnType>);
        static_assert(std::is_pointer_v<__PtrType>);
        return reinterpret_cast<__ReturnType>(
            const_cast<char*>(reinterpret_cast<const volatile char*>(p)) + offset
        );
    }

    //
    //  Print memory data in [lpMemBegin, lpMemEnd)
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must >= `from`
    //
    void PrintMemory(const void* lpMemBegin, const void* lpMemEnd, const void* lpBase) noexcept;

    //
    //  Print memory data in [lpMem, lpMem + cbMem)
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must >= `from`
    //
    void PrintMemory(const void* lpMem, size_t cbMem, const void* lpBase) noexcept;

    void PrintBytes(const void* lpMemBegin, const void* lpMemEnd) noexcept;
    void PrintBytes(const void* lpMem, size_t cbMem) noexcept;

    [[nodiscard]]
    bool IsValidDirectoryPath(PCTSTR lpszDirectoryPath) noexcept;

    [[nodiscard]]
    bool IsValidFilePath(PCTSTR lpszFilePath) noexcept;

    [[nodiscard]]
    bool IsWineEnvironment() noexcept;

    std::xstring GetCurrentWorkingDirectory();
}

