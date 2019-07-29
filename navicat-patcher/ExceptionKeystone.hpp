#pragma once
#include "../common/Exception.hpp"
#include <keystone/keystone.h>

namespace nkg {

    class KeystoneError final : public Exception {
    private:

        ks_err pvt_ErrorCode;

    public:

        KeystoneError(const char* File, unsigned Line, ks_err ErrorCode, const char* Message) noexcept :
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
            return ks_strerror(pvt_ErrorCode);
        }
    };

}
