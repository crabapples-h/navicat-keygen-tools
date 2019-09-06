#pragma once
#include <Exception.hpp>
#include <capstone/capstone.h>

namespace nkg {

    class CapstoneError final : public Exception {
    private:

        cs_err _ErrorCode;
        std::xstring _ErrorString;

    public:

        CapstoneError(PCTSTR SourceFile, SIZE_T SourceLine, cs_err CapstoneErrorCode, PCTSTR CustomMessage) noexcept :
            Exception(SourceFile, SourceLine, CustomMessage),
            _ErrorCode(CapstoneErrorCode),
            _ErrorString(std::xstring_extension{}, cs_strerror(CapstoneErrorCode), CP_UTF8) {}

        [[nodiscard]]
        virtual bool HasErrorCode() const noexcept override {
            return true;
        }

        [[nodiscard]]
        virtual ULONG_PTR ErrorCode() const noexcept override {
            return _ErrorCode;
        }

        [[nodiscard]]
        virtual PCTSTR ErrorString() const noexcept override {
            return _ErrorString.c_str();
        }
    };

}
