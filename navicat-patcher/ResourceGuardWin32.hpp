#pragma once
#include "ResourceGuard.hpp"
#include <windows.h>

struct GenericHandleTraits {
    using HandleType = HANDLE;
    static inline const HandleType InvalidValue = NULL;
    static constexpr auto& Releasor = CloseHandle;
};

struct FileHandleTraits {
    using HandleType = HANDLE;
    static inline const HandleType InvalidValue = INVALID_HANDLE_VALUE;
    static constexpr auto& Releasor = CloseHandle;
};

struct MapViewTraits {
    using HandleType = PVOID;
    static inline const HandleType InvalidValue = NULL;
    static constexpr auto& Releasor = UnmapViewOfFile;
};

