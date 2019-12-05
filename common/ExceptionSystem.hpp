#pragma once
#include "Exception.hpp"
#include <string.h>

namespace ARL {

    class SystemError final : public Exception {
    private:

        int m_ErrorCode;

    public:

        template<typename... __ArgTypes>
        SystemError(const char* SourceFile, size_t SourceLine, int ErrorCode, const char* Format, __ArgTypes&&... Args) noexcept :
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
            return strerror(m_ErrorCode);
        }
    };

}