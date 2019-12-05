#pragma once
#include <stddef.h>
#include <string>

namespace nkg::Misc {

    //
    //  Print memory data in [lpMemBegin, lpMemEnd)
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //
    void PrintMemory(const void* lpMemBegin, const void* lpMemEnd, const void* lpBase) noexcept;

    //
    //  Print memory data in [lpMem, lpMem + cbMem)
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //
    void PrintMemory(const void* lpMem, size_t cbMem, const void* lpBase) noexcept;

    [[nodiscard]]
    bool FsIsExist(std::string_view szPath);

    [[nodiscard]]
    bool FsIsFile(std::string_view szPath);

    [[nodiscard]]
    bool FsIsDirectory(std::string_view szPath);

    void FsCopyFile(std::string_view szSourcePath, std::string_view szDestinationPath);

    void FsDeleteFile(std::string_view szPath);

    std::string FsCurrentWorkingDirectory();

}

