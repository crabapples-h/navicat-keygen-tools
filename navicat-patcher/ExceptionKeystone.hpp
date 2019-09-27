#pragma once
#include <Exception.hpp>
#include <keystone/keystone.h>

namespace nkg {

    class KeystoneError final : public Exception {
    private:

        ks_err _ErrorCode;
        std::xstring _ErrorString;

    public:

        KeystoneError(PCTSTR SourceFile, SIZE_T SourceLine, ks_err KeystoneErrorCode, PCTSTR CustomMessage) noexcept :
            Exception(SourceFile, SourceLine, CustomMessage),
            _ErrorCode(KeystoneErrorCode),
            _ErrorString(std::xstring_extension{}, ks_strerror(KeystoneErrorCode), CP_UTF8) {}

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

