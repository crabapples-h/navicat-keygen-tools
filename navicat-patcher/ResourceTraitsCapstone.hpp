#pragma once
#include <capstone/capstone.h>
#include "ExceptionCapstone.hpp"

struct CapstoneHandleTraits {
    using HandleType = csh;

    static inline const HandleType InvalidValue = 0;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(HandleType& Handle) {
        auto err = cs_close(&Handle);
        if (err != CS_ERR_OK) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::CapstoneError(__FILE__, __LINE__, err, "ks_close failed.");
        }
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

