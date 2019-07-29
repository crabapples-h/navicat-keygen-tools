#pragma once
#include "Exception.hpp"
#include <string.h> // NOLINT

namespace nkg {

    class SystemError final : public Exception {
    private:

        int pvt_ErrorCode;

    public:

        SystemError(const char* File, unsigned Line, int ErrorCode, const char* Message) noexcept :
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
            return strerror(pvt_ErrorCode);
        }
    };

}