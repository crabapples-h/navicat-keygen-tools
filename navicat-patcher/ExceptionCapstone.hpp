#pragma once
#include <capstone/capstone.h>
#include "Exception.hpp"

namespace ARL {

    class CapstoneError final : public Exception {
    private:

        cs_err m_ErrorCode;

    public:

        template<typename... __ArgTypes>
        CapstoneError(const char* SourceFile, size_t SourceLine, cs_err ErrorCode, const char* Format, __ArgTypes&&... Args) noexcept :
            Exception(SourceFile, SourceLine, Format, std::forward<__ArgTypes>(Args)...),
            m_ErrorCode(ErrorCode) {}

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool HasErrorCode() const noexcept override {
            return true;
        }

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual intptr_t ErrorCode() const noexcept override {
            return m_ErrorCode;
        }

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual const char* ErrorString() const noexcept override {
            return cs_strerror(m_ErrorCode);
        }
    };

}

