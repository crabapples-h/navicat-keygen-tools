#pragma once
#include <keystone/keystone.h>
#include "ExceptionKeystone.hpp"

namespace ARL::ResourceTraits {

    struct KeystoneHandle {
        using HandleType = ks_engine*;

        static inline const HandleType InvalidValue = nullptr;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) {
            auto err = ks_close(Handle);
            if (err != KS_ERR_OK) {
                throw ARL::KeystoneError(__BASE_FILE__, __LINE__, err, "ks_close failed.");
            }
        }
    };

    struct KeystoneMalloc {
        using HandleType = uint8_t*;

        static inline const HandleType InvalidValue = nullptr;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) noexcept {
            ks_free(Handle);
        }
    };

}

