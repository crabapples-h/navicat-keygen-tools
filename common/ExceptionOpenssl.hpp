#pragma once
#include "Exception.hpp"
#include <openssl/err.h>

namespace ARL {

    class OpensslError final : public Exception {
    private:

        unsigned long m_ErrorCode;

    public:

        template<typename... __ArgTypes>
        OpensslError(const char* SourceFile, size_t SourceLine, unsigned long ErrorCode, const char* Format, __ArgTypes&&... Args) noexcept :
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
            static bool loaded = false;
            if (loaded == false) {
                ERR_load_crypto_strings();
                loaded = true;
            }
            return ERR_reason_error_string(m_ErrorCode);
        }
    };

}


