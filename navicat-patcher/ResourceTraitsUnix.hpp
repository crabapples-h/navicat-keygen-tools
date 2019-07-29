#pragma once
#include <errno.h>  // NOLINT
#include <unistd.h>
#include <sys/mman.h>
#include "../common/ExceptionSystem.hpp"

struct FileHandleTraits {
    using HandleType = int;

    static inline const HandleType InvalidValue = -1;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) {
        if (close(Handle) != 0) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::SystemError(__FILE__, __LINE__, errno, "close failed.");
        }
    }
};

struct MapViewTraits {
    using HandleType = void*;

    static inline const HandleType InvalidValue = MAP_FAILED;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }
};

