#pragma once
#include <openssl/err.h>
#include "Exception.hpp"

namespace nkg {

    class OpensslError final : public Exception {
    private:

        unsigned long pvt_ErrorCode;

    public:

        OpensslError(const char* File, unsigned Line, unsigned long ErrorCode, const char* Message) noexcept :
            Exception(File, Line, Message),
            pvt_ErrorCode(ErrorCode) {}

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool HasErrorCode() const noexcept override {
            return true;
        }

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual intptr_t ErrorCode() const noexcept override {
            return pvt_ErrorCode;
        }

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual const char* ErrorString() const noexcept override {
            ERR_load_crypto_strings();
            return ERR_reason_error_string(pvt_ErrorCode);
        }
    };

}


