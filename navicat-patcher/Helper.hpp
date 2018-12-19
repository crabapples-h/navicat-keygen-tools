#pragma once
#include <stddef.h>
#include <stdio.h>

namespace Helper {

    //
    //  Print memory data in [from, to) at least
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must >= `from`
    //
    void PrintMemory(const void* from, const void* to, const void* base);

    void ErrorReport(const char* at, size_t line, const char* msg);
    void ErrorReport(const char* at, size_t line, const char* msg, int err_code);

    template<typename _Type>
    struct ResourceGuard {
        _Type* ptr;

        explicit ResourceGuard(_Type* p) noexcept : ptr(p) {}

        ~ResourceGuard() {
            if (ptr) {
                delete ptr;
                ptr = nullptr;
            }
        }
    };
}

#define REPORT_ERROR(msg) Helper::ErrorReport(__FUNCTION__, __LINE__, msg)
#define REPORT_ERROR_WITH_CODE(msg) Helper::ErrorReport(__FUNCTION__, __LINE__, msg, errno)
#define PRINT_MESSAGE(msg) puts(msg)
