#pragma once
#include "Exception.hpp"

#if defined(CAPSTONE_ENGINE_H)  // if include <capstone/capstone.h>

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

#endif

