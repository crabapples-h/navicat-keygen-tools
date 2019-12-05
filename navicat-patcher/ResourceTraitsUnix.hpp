#pragma once
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include "ExceptionSystem.hpp"

namespace ARL::ResourceTraits {

    struct FileDescriptor {
        using HandleType = int;

        static inline const HandleType InvalidValue = -1;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) {
            if (close(Handle) != 0) {
                throw ARL::SystemError(__BASE_FILE__, __LINE__, errno, "close failed.");
            }
        }
    };

    struct MapView {
        using HandleType = void*;

        static inline const HandleType InvalidValue = MAP_FAILED;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }
    };

}

