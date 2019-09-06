#pragma once
#include <windows.h>
#include <xstring.hpp>

namespace nkg {

    enum class NavicatLanguage {
        English,
        SimplifiedChinese,
        TraditionalChinese,
        Japanese,
        Polish,
        Spanish,
        French,
        German,
        Korean,
        Russian,
        Portuguese
    };

    enum class NavicatProductType {
        DataModeler,
        Premium,
        MySQL,
        PostgreSQL,
        Oracle,
        SQLServer,
        SQLite,
        MariaDB,
        MongoDB,
        ReportViewer
    };

    class SerialNumberGenerator {
    private:

        BYTE _Data[10];
        std::xstring _SerialNumberShort;
        std::xstring _SerialNumberLong;

    public:

        SerialNumberGenerator() noexcept;

        void SetLanguageSignature(NavicatLanguage Language) noexcept;
        void SetLanguageSignature(BYTE LanguageSignature0, BYTE LanguageSignature1) noexcept;

        void SetProductSignature(NavicatProductType ProductType) noexcept;
        void SetProductSignature(BYTE ProductSignature) noexcept;

        void SetVersion(BYTE Version);

        void Generate();

        [[nodiscard]]
        const std::xstring& GetSerialNumberShort() const noexcept;
        [[nodiscard]]
        const std::xstring& GetSerialNumberLong() const noexcept;

        void ShowInConsole() const;
    };

}

