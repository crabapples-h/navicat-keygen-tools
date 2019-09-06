#pragma once
#include <capstone/capstone.h>

struct CapstoneHandleTraits {
    using HandleType = csh;

    static inline const HandleType InvalidValue = NULL;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(HandleType& Handle) noexcept {
        cs_close(&Handle);
    }
};

struct CapstoneInsnTraits {
    using HandleType = cs_insn*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) noexcept {
        cs_free(Handle, 1);
    }
};

