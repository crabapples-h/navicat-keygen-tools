#pragma once
#include "ResourceGuard.hpp"
#include <capstone/capstone.h>

struct CapstoneHandleTraits {
    using HandleType = csh;
    static inline const HandleType InvalidValue = 0;
    static inline void Releasor(csh Handle) {
        cs_close(&Handle);
    }
};

