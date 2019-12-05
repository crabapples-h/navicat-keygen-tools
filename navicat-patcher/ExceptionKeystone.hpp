#pragma once
#include <keystone/keystone.h>
#include "Exception.hpp"

namespace ARL {

    class KeystoneError final : public Exception {
    private:

        ks_err m_ErrorCode;

    public:

        template<typename... __ArgTypes>
        KeystoneError(const char* SourceFile, size_t SourceLine, ks_err ErrorCode, const char* Format, __ArgTypes&&... Args) noexcept :
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
            return ks_strerror(m_ErrorCode);
        }
    };

}

