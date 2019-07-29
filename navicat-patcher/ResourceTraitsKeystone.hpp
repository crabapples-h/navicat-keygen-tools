#pragma once
#include <keystone/keystone.h>
#include "ExceptionKeystone.hpp"

struct KeystoneHandleTraits {
    using HandleType = ks_engine*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) {
        auto err = ks_close(Handle);
        if (err != KS_ERR_OK) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::KeystoneError(__FILE__, __LINE__, err, "ks_close failed.");
        }
    }
};

struct KeystoneMallocTraits {
    using HandleType = uint8_t*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) noexcept {
        ks_free(Handle);
    }
};

