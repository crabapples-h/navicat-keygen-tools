#pragma once
#include <stdint.h>
#include <string>

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

        uint8_t     m_Data[10];
        std::string m_SerialNumberShort;
        std::string m_SerialNumberLong;

    public:

        SerialNumberGenerator() noexcept;

        void SetLanguageSignature(NavicatLanguage Language) noexcept;
        void SetLanguageSignature(uint8_t LanguageSignature0, uint8_t LanguageSignature1) noexcept;

        void SetProductSignature(NavicatProductType ProductType) noexcept;
        void SetProductSignature(uint8_t ProductSignature) noexcept;

        void SetVersion(uint8_t Version);

        void Generate();

        [[nodiscard]]
        const std::string& GetSerialNumberShort() const noexcept;
        
        [[nodiscard]]
        const std::string& GetSerialNumberLong() const noexcept;

        void ShowInConsole() const;
    };

}

