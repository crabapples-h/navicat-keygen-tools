#pragma once
#include "Exception.hpp"
#include <system_error>

class SystemError : public Exception {
private:
    const std::error_code _ErrorCode;
public:
    SystemError(const char* FileName,
                int Line,
                unsigned long Code,
                const char* Message) noexcept :
        Exception(FileName, Line, Message),
        _ErrorCode(Code, std::system_category()) {}

    virtual bool HasErrorCode() const noexcept override {
        return true;
    }

    virtual unsigned long ErrorCode() const noexcept override {
        return _ErrorCode.value();
    }

    virtual const char* ErrorString() const noexcept override {
        return _ErrorCode.message().c_str();
    }
};

