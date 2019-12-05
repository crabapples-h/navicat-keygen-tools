#pragma once
#include "Exception.hpp"

namespace ARL {

#pragma push_macro("DECLARE_NEW_EXCEPTION")
#undef DECLARE_NEW_EXCEPTION

#define DECLARE_NEW_EXCEPTION(name)                                                                             \
    class name final : public Exception {                                                                       \
    public:                                                                                                     \
        template<typename... __ArgTypes>                                                                        \
        name(const char* SourceFile, size_t SourceLine, const char* Format, __ArgTypes&&... Args) noexcept :    \
            Exception(SourceFile, SourceLine, Format, std::forward<__ArgTypes>(Args)...) {}                     \
    }

    DECLARE_NEW_EXCEPTION(AssertionError);
    DECLARE_NEW_EXCEPTION(EOFError);
    DECLARE_NEW_EXCEPTION(IndexError);
    DECLARE_NEW_EXCEPTION(KeyError);
    DECLARE_NEW_EXCEPTION(NotImplementedError);
    DECLARE_NEW_EXCEPTION(OverflowError);
    DECLARE_NEW_EXCEPTION(ValueError);

#undef DECLARE_NEW_EXCEPTION
#pragma pop_macro("DECLARE_NEW_EXCEPTION")

}

