#pragma once
#include "Exception.hpp"
#include <openssl/err.h>

namespace nkg {

    class OpensslError final : public Exception {
    private:

        unsigned long _ErrorCode;
        std::xstring _ErrorString;

    public:

        OpensslError(PCTSTR SourceFile, SIZE_T SourceLine, unsigned long OpensslErrorCode, PCTSTR CustomMessage) noexcept :
            Exception(SourceFile, SourceLine, CustomMessage),
            _ErrorCode(OpensslErrorCode) 
        {
            static bool CryptoStringsLoaded = false;
            if (CryptoStringsLoaded == false) {
                ERR_load_crypto_strings();
                CryptoStringsLoaded = true;
            }

            _ErrorString = std::xstring(std::xstring_extension{}, ERR_reason_error_string(_ErrorCode), CP_UTF8);
        }

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
