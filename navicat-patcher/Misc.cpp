#include "Misc.hpp"
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <filesystem>
#include "ExceptionSystem.hpp"

static jmp_buf g_jmbuf;

static void SIGSEGV_handler(int sig) {
    siglongjmp(g_jmbuf, 1);
}

//
//  read byte(s) at address `p` as __Type to `out`
//  succeed if return true, otherwise return false
//
template<typename __Type>
static inline bool probe_for_read(const void* p, void* out) {
    int r = sigsetjmp(g_jmbuf, 1);
    if (r == 0) {
        *reinterpret_cast<__Type*>(out) = *reinterpret_cast<const __Type*>(p);
        return true;
    } else {
        return false;
    }
}

namespace nkg::Misc {

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
                    printf("+0x%.*zx  ", static_cast<int>(2 * sizeof(void*)), d);
                } else {
                    printf("-0x%.*zx  ", static_cast<int>(2 * sizeof(void*)), d);
                }
            } else {
                printf("0x%.*zx  ", static_cast<int>(2 * sizeof(void*)), reinterpret_cast<uintptr_t>(pbBegin));
            }

            for (int i = 0; i < 16; ++i) {
                if (pbBegin + i < lpMemBegin || pbBegin + i >= lpMemEnd) {
                    printf("   ");
                    Values[i] = 0xfffe;
                } else if (probe_for_read<uint8_t>(pbBegin + i, Values + i)) {
                    printf("%02x ", Values[i]);
                } else {
                    printf("?? ");
                    Values[i] = 0xffff;
                }
            }

            printf(" ");

            for (int i = 0; i < 16; ++i) {
                if (0x20 <= Values[i] && Values[i] < 0x7f) {
                    printf("%c", Values[i]);
                } else if (Values[i] == 0xfffe) {
                    printf(" ");
                } else {
                    printf(".");
                }
            }

            printf("\n");

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

    [[nodiscard]]
    bool FsIsExist(std::string_view szPath) {
        std::error_code ec;
        if (std::filesystem::exists(szPath, ec)) {
            return true;
        } else {
            if (ec) {
                throw ARL::SystemError(__BASE_FILE__, __LINE__, ec.value(), "std::filesystem::exists failed.");
            } else {
                return false;
            }
        }
    }

    [[nodiscard]]
    bool FsIsFile(std::string_view szPath) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(szPath, ec)) {
            return true;
        } else {
            if (ec) {
                throw ARL::SystemError(__BASE_FILE__, __LINE__, ec.value(), "std::filesystem::is_regular_file failed.");
            } else {
                return false;
            }
        }
    }
    
    [[nodiscard]]
    bool FsIsDirectory(std::string_view szPath) {
        std::error_code ec;
        if (std::filesystem::is_directory(szPath, ec)) {
            return true;
        } else {
            if (ec) {
                throw ARL::SystemError(__BASE_FILE__, __LINE__, ec.value(), "std::filesystem::is_directory failed.");
            } else {
                return false;
            }
        }
    }

    void FsCopyFile(std::string_view szSourcePath, std::string_view szDestinationPath) {
        std::error_code ec;
        if (std::filesystem::copy_file(szSourcePath, szDestinationPath, ec) == false) {
            throw ARL::SystemError(__BASE_FILE__, __LINE__, ec.value(), "std::filesystem::copy_file failed.");
        }
    }

    void FsDeleteFile(std::string_view szPath) {
        std::error_code ec;
        if (std::filesystem::remove(szPath, ec) == false) {
            throw ARL::SystemError(__BASE_FILE__, __LINE__, ec.value(), "std::filesystem::remove failed.");
        }
    }

    std::string FsCurrentWorkingDirectory() {
        std::error_code ec;
        std::string path = std::filesystem::current_path(ec);
        if (ec) {
            throw ARL::SystemError(__BASE_FILE__, __LINE__, ec.value(), "std::filesystem::current_path failed.");
        } else {
            return path;
        }
    }

}

