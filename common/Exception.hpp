#pragma once
#include <stddef.h> // NOLINT
#include <stdint.h> // NOLINT

namespace nkg {

    class Exception {
    private:

        const char* pvt_File;
        const char* pvt_Message;
        size_t      pvt_Line;

    public:

        Exception(const char* File, size_t Line, const char* Message) noexcept :
            pvt_File(File),
            pvt_Message(Message),
            pvt_Line(Line) {}

        [[nodiscard]]
        const char* File() const noexcept {
            return pvt_File;
        }

        [[nodiscard]]
        size_t Line() const noexcept {
            return pvt_Line;
        }

        [[nodiscard]]
        const char* Message() const noexcept {
            return pvt_Message;
        }

        [[nodiscard]]
        virtual bool HasErrorCode() const noexcept {
            return false;
        }

        [[nodiscard]]
        virtual intptr_t ErrorCode() const noexcept {
            return 0;
        }

        [[nodiscard]]
        virtual const char* ErrorString() const noexcept {
            return nullptr;
        }
    };

}

