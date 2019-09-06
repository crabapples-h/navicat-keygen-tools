#include "SerialNumberGenerator.hpp"
#include <ExceptionUser.hpp>
#include <iostream>

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-keygen\\CollectInformation.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace std {
#if defined(_UNICODE) || defined(UNICODE)
    static auto& xcin = wcin;
    static auto& xcout = wcout;
    static auto& xcerr = wcerr;
#else
    static auto& xcin = cin;
    static auto& xcout = cout;
    static auto& xcerr = cerr;
#endif
}

namespace nkg {

    [[nodiscard]]
    static int ReadInt(int MinVal, int MaxVal, PCTSTR lpszPrompt, PCTSTR lpszErrorMessage) {
        int val;
        std::xstring s;
        while (true) {
            std::xcout << lpszPrompt;
            if (!std::getline(std::xcin, s)) {
                throw UserAbortionError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Abort."));
            }

            if (s.empty())
                continue;

            try {
                val = std::stoi(s, nullptr, 0);
                if (MinVal <= val && val <= MaxVal) {
                    return val;
                } else {
                    throw std::invalid_argument("");
                }
            } catch (std::invalid_argument&) {
                std::xcout << lpszErrorMessage << std::endl;
            }
        }
    }

    [[nodiscard]]
    static int ReadInt(int MinVal, int MaxVal, int DefaultVal, PCTSTR lpszPrompt, PCTSTR lpszErrorMessage) {
        int val;
        std::xstring s;
        while (true) {
            std::xcout << lpszPrompt;
            if (!std::getline(std::xcin, s)) {
                throw UserAbortionError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Abort."));
            }

            if (s.empty()) {
                return DefaultVal;
            }

            try {
                val = std::stoi(s, nullptr, 0);
                if (MinVal <= val && val <= MaxVal) {
                    return val;
                } else {
                    throw std::invalid_argument("");
                }
            } catch (std::invalid_argument&) {
                std::xcout << lpszErrorMessage << std::endl;
            }
        }
    }

    [[nodiscard]]
    SerialNumberGenerator CollectInformationNormal() {
        SerialNumberGenerator Generator;

        std::xcout << TEXT("[*] Select Navicat product:")   << std::endl;
        std::xcout << TEXT(" 0. DataModeler")               << std::endl;
        std::xcout << TEXT(" 1. Premium")                   << std::endl;
        std::xcout << TEXT(" 2. MySQL")                     << std::endl;
        std::xcout << TEXT(" 3. PostgreSQL")                << std::endl;
        std::xcout << TEXT(" 4. Oracle")                    << std::endl;
        std::xcout << TEXT(" 5. SQLServer")                 << std::endl;
        std::xcout << TEXT(" 6. SQLite")                    << std::endl;
        std::xcout << TEXT(" 7. MariaDB")                   << std::endl;
        std::xcout << TEXT(" 8. MongoDB")                   << std::endl;
        std::xcout << TEXT(" 9. ReportViewer")              << std::endl;
        std::xcout << std::endl;
        Generator.SetProductSignature(
            static_cast<NavicatProductType>(ReadInt(0, 9, TEXT("(Input index)> "), TEXT("Invalid index.")))
        );

        std::xcout << std::endl;
        std::xcout << TEXT("[*] Select product language:")  << std::endl;
        std::xcout << TEXT(" 0. English")                   << std::endl;
        std::xcout << TEXT(" 1. Simplified Chinese")        << std::endl;
        std::xcout << TEXT(" 2. Traditional Chinese")       << std::endl;
        std::xcout << TEXT(" 3. Japanese")                  << std::endl;
        std::xcout << TEXT(" 4. Polish")                    << std::endl;
        std::xcout << TEXT(" 5. Spanish")                   << std::endl;
        std::xcout << TEXT(" 6. French")                    << std::endl;
        std::xcout << TEXT(" 7. German")                    << std::endl;
        std::xcout << TEXT(" 8. Korean")                    << std::endl;
        std::xcout << TEXT(" 9. Russian")                   << std::endl;
        std::xcout << TEXT(" 10. Portuguese")               << std::endl;
        std::xcout << std::endl;
        Generator.SetLanguageSignature(
            static_cast<NavicatLanguage>(ReadInt(0, 10, TEXT("(Input index)> "), TEXT("Invalid index.")))
        );

        std::xcout << std::endl;
        std::xcout << TEXT("[*] Input major version number:") << std::endl;
        Generator.SetVersion(
            static_cast<BYTE>(ReadInt(0, 15, 12, TEXT("(range: 0 ~ 15, default: 12)> "), TEXT("Invalid number.")))
        );

        std::xcout << std::endl;
        return Generator;
    }

    [[nodiscard]]
    SerialNumberGenerator CollectInformationAdvanced() {
        SerialNumberGenerator Generator;

        std::xcout << TEXT("[*] Navicat Product Signature:") << std::endl;
        Generator.SetProductSignature(
            static_cast<BYTE>(ReadInt(0x00, 0xff, TEXT("(range: 0x00 ~ 0xFF)> "), TEXT("Invalid number.")))
        );

        std::xcout << std::endl;
        std::xcout << TEXT("[*] Navicat Language Signature 0:") << std::endl;
        auto s1 = static_cast<BYTE>(ReadInt(0x00, 0xff, TEXT("(range: 0x00 ~ 0xFF)> "), TEXT("Invalid number.")));
        std::xcout << std::endl;
        std::xcout << TEXT("[*] Navicat Language Signature 1:") << std::endl;
        auto s2 = static_cast<BYTE>(ReadInt(0x00, 0xff, TEXT("(range: 0x00 ~ 0xFF)> "), TEXT("Invalid number.")));
        Generator.SetLanguageSignature(s1, s2);

        std::xcout << std::endl;
        std::xcout << TEXT("[*] Input major version number:") << std::endl;
        Generator.SetVersion(
            static_cast<BYTE>(ReadInt(0, 15, 12, TEXT("(range: 0 ~ 15, default: 12)> "), TEXT("Invalid number.")))
        );

        std::xcout << std::endl;
        return Generator;
    }
}

