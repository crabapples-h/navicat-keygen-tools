#pragma once
#include "ResourceGuard.hpp"
#include <capstone/capstone.h>

struct CapstoneHandleTraits {
    using HandleType = csh;
    static const HandleType InvalidValue;
    static inline void Releasor(csh Handle) {
        cs_close(&Handle);
    }
};

inline const CapstoneHandleTraits::HandleType
    CapstoneHandleTraits::InvalidValue = 0;

