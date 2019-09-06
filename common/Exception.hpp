#pragma once
#include <windows.h>
#include "xstring.hpp"
#include <vector>

namespace nkg {

    class Exception {
    private:

        PCTSTR _SourceFile;
        SIZE_T _SourceLine;
        PCTSTR _Message;
        std::vector<std::xstring> _Hints;

    public:

        Exception(PCTSTR SourceFile, SIZE_T SourceLine, PCTSTR CustomMessage) noexcept :
            _SourceFile(SourceFile),
            _SourceLine(SourceLine),
            _Message(CustomMessage) {}

        [[nodiscard]]
        auto File() const noexcept {
            return _SourceFile;
        }
        
        [[nodiscard]]
        auto Line() const noexcept {
            return _SourceLine;
        }

        [[nodiscard]]
        auto Message() const noexcept {
            return _Message;
        }

        auto& AddHint(const std::xstring& Hint) {
            _Hints.emplace_back(Hint);
            return *this;
        }

        [[nodiscard]]
        const auto& Hints() const noexcept {
            return _Hints;
        }

        [[nodiscard]]
        virtual bool HasErrorCode() const noexcept {
            return false;
        }

        [[nodiscard]]
        virtual ULONG_PTR ErrorCode() const noexcept {
            return 0;
        }

        [[nodiscard]]
        virtual PCTSTR ErrorString() const noexcept {
            return nullptr;
        }

        virtual ~Exception() = default;
    };

}
