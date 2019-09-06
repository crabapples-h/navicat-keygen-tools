#pragma once
#include <windows.h>

struct GenericHandleTraits {
    using HandleType = HANDLE;

    static inline const HandleType InvalidValue = NULL;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) noexcept {
        CloseHandle(Handle);
    }
};

struct FileHandleTraits {
    using HandleType = HANDLE;

    static inline const HandleType InvalidValue = INVALID_HANDLE_VALUE;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) noexcept {
        CloseHandle(Handle);
    }
};

struct MapViewHandleTraits {
    using HandleType = PVOID;

    static inline const HandleType InvalidValue = NULL;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) noexcept {
        UnmapViewOfFile(Handle);
    }
};
