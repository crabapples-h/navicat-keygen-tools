#pragma once
#include <string>
#include <sstream>
#include <iostream>
#include <stddef.h>
#include <system_error>

class Exception {
private:
    const char* const _$$_SourceFile;
    const size_t _$$_SourceLine;
    const char* const _$$_CustomMessage;
public:

    Exception(const char* FileName, size_t Line, const char* Message) noexcept :
            _$$_SourceFile(FileName),
            _$$_SourceLine(Line),
            _$$_CustomMessage(Message) {}

    const char* SourceFile() const noexcept {
        return _$$_SourceFile;
    }

    size_t SourceLine() const noexcept {
        return _$$_SourceLine;
    }

    const char* CustomMessage() const noexcept {
        return _$$_CustomMessage;
    }

    virtual bool HasErrorCode() const noexcept {
        return false;
    }

    virtual unsigned long ErrorCode() const noexcept {
        return 0;
    }

    virtual const char* ErrorString() const noexcept {
        return nullptr;
    }

};

class SystemError : public Exception {
private:
    const std::error_code _ErrorCode;
    const std::string _ErrorString;
public:
    SystemError(const char* FileName,
                size_t Line,
                int Code,
                const char* Message) noexcept :
        Exception(FileName, Line, Message),
        _ErrorCode(Code, std::system_category()),
        _ErrorString(_ErrorCode.message()) {}

    virtual bool HasErrorCode() const noexcept override {
        return true;
    }

    virtual unsigned long ErrorCode() const noexcept override {
        return _ErrorCode.value();
    }

    virtual const char* ErrorString() const noexcept override {
        return _ErrorString.c_str();
    }
};

