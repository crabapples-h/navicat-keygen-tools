#pragma once
#include "../common/Exception.hpp"
#include <capstone/capstone.h>

namespace nkg {

    class CapstoneError final : public Exception {
    private:

        cs_err pvt_ErrorCode;

    public:

        CapstoneError(const char* File, unsigned Line, cs_err ErrorCode, const char* Message) noexcept :
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
            return cs_strerror(pvt_ErrorCode);
        }
    };

}
