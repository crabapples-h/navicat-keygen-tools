#pragma once
#include "ResourceGuard.hpp"

#if defined(CAPSTONE_ENGINE_H)

struct CapstoneHandleTraits {
    using HandleType = csh;
    static inline const HandleType InvalidValue = 0;
    static inline void Releasor(csh Handle) {
        cs_close(&Handle);
    }
};

#endif

