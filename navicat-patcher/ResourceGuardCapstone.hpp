#pragma once
#include "ResourceGuard.hpp"

#if defined(CAPSTONE_ENGINE_H)

struct CapstoneHandleTraits {
    using HandleType = csh;
    static inline const HandleType InvalidValue = 0;
    static inline void Releasor(HandleType Handle) {
        cs_close(&Handle);
    }
};

template<typename __Type>
struct CapstoneMallocTraits {
    using HandleType = __Type*;
    static inline const HandleType InvalidValue = nullptr;
    static inline void Releasor(HandleType Handle) {
        cs_free(Handle, 1);
    }
};

#endif

