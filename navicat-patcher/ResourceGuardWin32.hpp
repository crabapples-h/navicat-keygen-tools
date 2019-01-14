#pragma once
#include "ResourceGuard.hpp"
#include <windows.h>

struct GenericHandleTraits {
    using HandleType = HANDLE;
    static const HandleType InvalidValue;
    static constexpr auto& Releasor = CloseHandle;
};

inline const GenericHandleTraits::HandleType 
    GenericHandleTraits::InvalidValue = NULL;

struct FileHandleTraits {
    using HandleType = HANDLE;
    static const HandleType InvalidValue;
    static constexpr auto& Releasor = CloseHandle;
};

inline const FileHandleTraits::HandleType
    FileHandleTraits::InvalidValue = INVALID_HANDLE_VALUE;

struct MapViewTraits {
    using HandleType = PVOID;
    static const HandleType InvalidValue;
    static constexpr auto& Releasor = UnmapViewOfFile;
};

inline const MapViewTraits::HandleType
    MapViewTraits::InvalidValue = NULL;

