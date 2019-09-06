#pragma once
#include "Exception.hpp"

namespace nkg {

    class Win32Error final : public Exception {
    private:

        DWORD _ErrorCode;
        std::xstring _ErrorString;

    public:

        Win32Error(PCTSTR SourceFile, SIZE_T SourceLine, DWORD Win32ErrorCode, PCTSTR CustomMessage) noexcept :
            Exception(SourceFile, SourceLine, CustomMessage),
            _ErrorCode(Win32ErrorCode) 
        {
            PTSTR Text = NULL;
            FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                NULL,
                Win32ErrorCode,
                MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                reinterpret_cast<PTSTR>(&Text),
                0,
                NULL
            );
            if (Text) {
                _ErrorString = Text;
                LocalFree(Text);
            }
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
