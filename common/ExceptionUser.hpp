#pragma once
#include "Exception.hpp"

namespace nkg {

    class UserAbortionError final : public Exception {
    public:

        UserAbortionError(PCTSTR SourceFile, SIZE_T SourceLine, PCTSTR CustomMessage) noexcept :
            Exception(SourceFile, SourceLine, CustomMessage) {}

        [[nodiscard]]
        virtual bool HasErrorCode() const noexcept override {
            return false;
        }

        [[nodiscard]]
        virtual ULONG_PTR ErrorCode() const noexcept override {
            return 0;
        }

        [[nodiscard]]
        virtual PCTSTR ErrorString() const noexcept override {
            return nullptr;
        }
    };

}