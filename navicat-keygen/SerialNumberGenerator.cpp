#include "SerialNumberGenerator.hpp"
#include "Exception.hpp"
#include <openssl/rand.h>
#include <openssl/des.h>
#include <iostream>
#include <algorithm>
#include "Base32.hpp"

namespace nkg {

    SerialNumberGenerator::SerialNumberGenerator() noexcept :
        m_Data{ 0x68 , 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32 } {}

    void SerialNumberGenerator::SetLanguageSignature(NavicatLanguage Language) noexcept {
        switch (Language) {
            case NavicatLanguage::English:
                m_Data[5] = 0xAC;       // Must be 0xAC for English version.
                m_Data[6] = 0x88;       // Must be 0x88 for English version.
                break;
            case NavicatLanguage::SimplifiedChinese:
                m_Data[5] = 0xCE;       // Must be 0xCE for Simplified Chinese version.
                m_Data[6] = 0x32;       // Must be 0x32 for Simplified Chinese version.
                break;
            case NavicatLanguage::TraditionalChinese:
                m_Data[5] = 0xAA;       // Must be 0xAA for Traditional Chinese version.
                m_Data[6] = 0x99;       // Must be 0x99 for Traditional Chinese version.
                break;
            case NavicatLanguage::Japanese:
                m_Data[5] = 0xAD;       // Must be 0xAD for Japanese version. Discoverer: @dragonflylee
                m_Data[6] = 0x82;       // Must be 0x82 for Japanese version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::Polish:
                m_Data[5] = 0xBB;       // Must be 0xBB for Polish version. Discoverer: @dragonflylee
                m_Data[6] = 0x55;       // Must be 0x55 for Polish version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::Spanish:
                m_Data[5] = 0xAE;       // Must be 0xAE for Spanish version. Discoverer: @dragonflylee
                m_Data[6] = 0x10;       // Must be 0x10 for Spanish version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::French:
                m_Data[5] = 0xFA;       // Must be 0xFA for French version. Discoverer: @Deltafox79
                m_Data[6] = 0x20;       // Must be 0x20 for French version. Discoverer: @Deltafox79
                break;
            case NavicatLanguage::German:
                m_Data[5] = 0xB1;       // Must be 0xB1 for German version. Discoverer: @dragonflylee
                m_Data[6] = 0x60;       // Must be 0x60 for German version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::Korean:
                m_Data[5] = 0xB5;       // Must be 0xB5 for Korean version. Discoverer: @dragonflylee
                m_Data[6] = 0x60;       // Must be 0x60 for Korean version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::Russian:
                m_Data[5] = 0xEE;       // Must be 0xB5 for Russian version. Discoverer: @dragonflylee
                m_Data[6] = 0x16;       // Must be 0x60 for Russian version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::Portuguese:
                m_Data[5] = 0xCD;       // Must be 0xCD for Portuguese version. Discoverer: @dragonflylee
                m_Data[6] = 0x49;       // Must be 0x49 for Portuguese version. Discoverer: @dragonflylee
                break;
            default:
                break;
        }
    }

    void SerialNumberGenerator::SetLanguageSignature(uint8_t LanguageSignature0, uint8_t LanguageSignature1) noexcept {
        m_Data[5] = LanguageSignature0;
        m_Data[6] = LanguageSignature1;
    }

    void SerialNumberGenerator::SetProductSignature(NavicatProductType ProductType) noexcept {
        switch (ProductType) {
            case NavicatProductType::DataModeler:
                m_Data[7] = 0x84;
                break;
            case NavicatProductType::Premium:
                m_Data[7] = 0x65;
                break;
            case NavicatProductType::MySQL:
                m_Data[7] = 0x68;
                break;
            case NavicatProductType::PostgreSQL:
                m_Data[7] = 0x6C;
                break;
            case NavicatProductType::Oracle:
                m_Data[7] = 0x70;
                break;
            case NavicatProductType::SQLServer:
                m_Data[7] = 0x74;
                break;
            case NavicatProductType::SQLite:
                m_Data[7] = 0x78;
                break;
            case NavicatProductType::MariaDB:
                m_Data[7] = 0x7C;
                break;
            case NavicatProductType::MongoDB:
                m_Data[7] = 0x80;
                break;
            case NavicatProductType::ReportViewer:
                m_Data[7] = 0x0b;
            default:
                break;
        }
    }

    void SerialNumberGenerator::SetProductSignature(uint8_t ProductSignature) noexcept {
        m_Data[7] = ProductSignature;
    }

    void SerialNumberGenerator::SetVersion(uint8_t Version) {
        if (Version < 0x10) {
            m_Data[8] = static_cast<uint8_t>(Version << 4);
        } else {
            throw ARL::Exception(__BASE_FILE__, __LINE__, "Invalid version for Navicat.");
        }
    }

    void SerialNumberGenerator::Generate() {
        static auto translator = [](char c) {
#ifdef __APPLE__
            //static const char StandardBase32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            //static const char NavicatBase32[] =  "ABCDEFGH8JKLMN9PQRSTUVWXYZ234567";
            switch (c) {
                case 'I':
                    return '8';
                case 'O':
                    return '9';
                default:
                    return c;
            }
#else
            //static const char StandardBase32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            //static const char NavicatBase32[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            return c;
#endif
        };

        RAND_bytes(m_Data + 2, 3);

        const_DES_cblock key = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };
        DES_key_schedule schedule;
        DES_set_key_unchecked(&key, &schedule);
        DES_ecb_encrypt(
            reinterpret_cast<const_DES_cblock*>(m_Data + 2),
            reinterpret_cast<const_DES_cblock*>(m_Data + 2),
            &schedule,
            DES_ENCRYPT
        );

        
        m_SerialNumberShort = base32_encode(m_Data, sizeof(m_Data));
        std::transform(m_SerialNumberShort.begin(), m_SerialNumberShort.end(), m_SerialNumberShort.begin(), translator);

        m_SerialNumberLong.resize(20);
        snprintf(m_SerialNumberLong.data(), m_SerialNumberLong.length(), 
            "%.4s-%.4s-%.4s-%.4s",
            m_SerialNumberShort.c_str() + 0,
            m_SerialNumberShort.c_str() + 4,
            m_SerialNumberShort.c_str() + 8,
            m_SerialNumberShort.c_str() + 12
        );
        while (m_SerialNumberLong.back() == '\x00') {
            m_SerialNumberLong.pop_back();
        }
    }

    [[nodiscard]]
    const std::string& SerialNumberGenerator::GetSerialNumberShort() const noexcept {
        return m_SerialNumberShort;
    }

    [[nodiscard]]
    const std::string& SerialNumberGenerator::GetSerialNumberLong() const noexcept {
        return m_SerialNumberLong;
    }

    void SerialNumberGenerator::ShowInConsole() const {
        std::cout << "[*] Serial number:" << std::endl;
        std::cout << m_SerialNumberLong << std::endl;
        std::cout << std::endl;
    }
}

