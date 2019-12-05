#pragma once
#include <capstone/capstone.h>
#include "ExceptionCapstone.hpp"

namespace ARL::ResourceTraits {

    struct CapstoneHandle {
        using HandleType = csh;

        static inline const HandleType InvalidValue = 0;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(HandleType& Handle) {
            if (auto err = cs_close(&Handle); err != CS_ERR_OK) {
                throw ARL::CapstoneError(__BASE_FILE__, __LINE__, err, "ks_close failed.");
            }
        }
    };

    struct CapstoneInsn {
        using HandleType = cs_insn*;

        static inline const HandleType InvalidValue = nullptr;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) noexcept {
            cs_free(Handle, 1);
        }
    };

}

