#pragma once
#include <system_error>
#include <openssl/err.h>

namespace Patcher {

    class Exception {
    private:
        const char* const _FileName;
        const int _NumberOfLine;
        const char* _CustomMessage;
    public:

        Exception(const char* FileName, int Line, const char* Message) noexcept :
            _FileName(FileName),
            _NumberOfLine(Line),
            _CustomMessage(Message) {}

        const char* SourceFile() const noexcept {
            return _FileName;
        }

        int SourceLine() const noexcept {
            return _NumberOfLine;
        }

        const char* CustomMessage() const noexcept {
            return _CustomMessage;
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

}



