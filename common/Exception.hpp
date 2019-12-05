#pragma once
#include <stddef.h>
#include <stdint.h>
#include <exception>
#include <string>
#include <vector>
#include <utility>

namespace ARL {

    class Exception : public std::exception {
    private:

        const char*  m_SourceFile;
        const size_t m_SourceLine;
        std::string  m_Message;
        std::vector<std::string> m_Hints;

    public:

        template<typename... __ArgTypes>
        Exception(const char* SourceFile, size_t SourceLine, const char* Format, __ArgTypes&&... Args) noexcept :
            m_SourceFile(SourceFile),
            m_SourceLine(SourceLine)
        {
            if constexpr (sizeof...(Args) == 0) {
                m_Message.assign(Format);
            } else {
                int l;
                
                l = snprintf(nullptr, 0, Format, std::forward<__ArgTypes>(Args)...);
                if (l < 0) {
                    std::terminate();
                }

                m_Message.resize(l + 1);

                l = snprintf(m_Message.data(), m_Message.length(), Format, std::forward<__ArgTypes>(Args)...);
                if (l < 0) {
                    std::terminate();
                }

                while (m_Message.back() == '\x00') {
                    m_Message.pop_back();
                }
            }
        }

        [[nodiscard]]
        auto ExceptionFile() const noexcept {
            return m_SourceFile;
        }
        
        [[nodiscard]]
        auto ExceptionLine() const noexcept {
            return m_SourceLine;
        }

        [[nodiscard]]
        auto ExceptionMessage() const noexcept {
            return m_Message.c_str();
        }

        template<typename __HintType>
        auto& PushHint(__HintType&& Hint) noexcept {    // if an exception is thrown, just suppress and terminate.
            m_Hints.emplace_back(std::forward<__HintType>(Hint));
            return *this;
        }

        template<typename... __ArgTypes>
        auto& PushFormatHint(const char* Format, __ArgTypes&&... Args) noexcept {    // if an exception is thrown, just suppress and terminate.
            int l;
            std::string s;

            l = snprintf(nullptr, 0, Format, std::forward<__ArgTypes>(Args)...);
            if (l < 0) {
                std::terminate();
            }

            s.resize(l + 1);

            l = snprintf(s.data(), s.length(), Format, std::forward<__ArgTypes>(Args)...);
            if (l < 0) {
                std::terminate();
            }

            while (s.back() == '\x00') {
                s.pop_back();
            }

            m_Hints.emplace_back(std::move(s));

            return *this;
        }

        [[nodiscard]]
        const auto& Hints() const noexcept {
            return m_Hints;
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

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual const char* what() const noexcept override {
            return ExceptionMessage();
        }
    };

}

