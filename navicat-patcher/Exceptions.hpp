#pragma once
#include <system_error>
#include <openssl/err.h>
#include <capstone/capstone.h>

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

    class CapstoneError : public Exception {
    private:
        const cs_err _ErrorCode;
    public:
        CapstoneError(const char* FileName,
                      int Line,
                      cs_err Code,
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
            switch (_ErrorCode) {
                case CS_ERR_MEM:
                    return "Out-Of-Memory error.";
                case CS_ERR_ARCH:
                    return "Unsupported architecture.";
                case CS_ERR_HANDLE:   
                    return "Invalid handle.";
                case CS_ERR_CSH:      
                    return "Invalid csh argument.";
                case CS_ERR_MODE:     
                    return "Invalid/unsupported mode.";
                case CS_ERR_OPTION:   
                    return "Invalid/unsupported option.";
                case CS_ERR_DETAIL:   
                    return "Information is unavailable because detail option is OFF";
                case CS_ERR_MEMSETUP: 
                    return "Dynamic memory management uninitialized.";
                case CS_ERR_VERSION:  
                    return "Unsupported version (bindings).";
                case CS_ERR_DIET:     
                    return "Access irrelevant data in \"diet\" engine.";
                case CS_ERR_SKIPDATA: 
                    return "Access irrelevant data for \"data\" instruction in SKIPDATA mode.";
                case CS_ERR_X86_ATT:  
                    return "X86 AT&T syntax is unsupported (opt-out at compile time).";
                case CS_ERR_X86_INTEL: 
                    return "X86 Intel syntax is unsupported (opt-out at compile time).";
                case CS_ERR_X86_MASM: 
                    return "X86 Intel syntax is unsupported (opt-out at compile time).";
                default:
                    return nullptr;
            }
        }
    };

}



