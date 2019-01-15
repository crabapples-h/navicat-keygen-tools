#pragma once
#include "Exception.hpp"

#if defined(HEADER_ERR_H)   // if include <openssl/err.h>

class OpensslError : public Exception {
private:
    const unsigned long _ErrorCode;
public:

    OpensslError(const char* FileName,
                 int Line,
                 unsigned long Code,
                 const char* Message) noexcept :
        Exception(FileName, Line, Message),
        _ErrorCode(Code) {}

    virtual bool HasErrorCode() const noexcept override {
        return true;
    }

    virtual unsigned long ErrorCode() const noexcept override {
        return _ErrorCode;
    }

    virtual const char* ErrorString() const noexcept override {
        return ERR_error_string(_ErrorCode, nullptr);
    }

};

#endif
