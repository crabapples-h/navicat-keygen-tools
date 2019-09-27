#pragma once
#include <keystone/keystone.h>

struct KeystoneHandleTraits {
    using HandleType = ks_engine*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) noexcept {
        ks_close(Handle);
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

