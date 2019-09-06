#include "SerialNumberGenerator.hpp"
#include <Exception.hpp>
#include <openssl/des.h>
#include <NTSecAPI.h>
#include <iostream>

#pragma comment(lib, "Advapi32")

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-keygen\\NavicatKeygen.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace std {
#if defined(_UNICODE) || defined(UNICODE)
    static auto & xcin = wcin;
    static auto& xcout = wcout;
    static auto& xcerr = wcerr;
#else
    static auto& xcin = cin;
    static auto& xcout = cout;
    static auto& xcerr = cerr;
#endif
}

namespace nkg {

    SerialNumberGenerator::SerialNumberGenerator() noexcept :
        _Data{ 0x68 , 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32 } {}

    void SerialNumberGenerator::SetLanguageSignature(NavicatLanguage Language) noexcept {
        switch (Language) {
            case NavicatLanguage::English:
                _Data[5] = 0xAC;       // Must be 0xAC for English version.
                _Data[6] = 0x88;       // Must be 0x88 for English version.
                break;
            case NavicatLanguage::SimplifiedChinese:
                _Data[5] = 0xCE;       // Must be 0xCE for Simplified Chinese version.
                _Data[6] = 0x32;       // Must be 0x32 for Simplified Chinese version.
                break;
            case NavicatLanguage::TraditionalChinese:
                _Data[5] = 0xAA;       // Must be 0xAA for Traditional Chinese version.
                _Data[6] = 0x99;       // Must be 0x99 for Traditional Chinese version.
                break;
            case NavicatLanguage::Japanese:
                _Data[5] = 0xAD;       // Must be 0xAD for Japanese version. Discoverer: @dragonflylee
                _Data[6] = 0x82;       // Must be 0x82 for Japanese version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::Polish:
                _Data[5] = 0xBB;       // Must be 0xBB for Polish version. Discoverer: @dragonflylee
                _Data[6] = 0x55;       // Must be 0x55 for Polish version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::Spanish:
                _Data[5] = 0xAE;       // Must be 0xAE for Spanish version. Discoverer: @dragonflylee
                _Data[6] = 0x10;       // Must be 0x10 for Spanish version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::French:
                _Data[5] = 0xFA;       // Must be 0xFA for French version. Discoverer: @Deltafox79
                _Data[6] = 0x20;       // Must be 0x20 for French version. Discoverer: @Deltafox79
                break;
            case NavicatLanguage::German:
                _Data[5] = 0xB1;       // Must be 0xB1 for German version. Discoverer: @dragonflylee
                _Data[6] = 0x60;       // Must be 0x60 for German version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::Korean:
                _Data[5] = 0xB5;       // Must be 0xB5 for Korean version. Discoverer: @dragonflylee
                _Data[6] = 0x60;       // Must be 0x60 for Korean version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::Russian:
                _Data[5] = 0xEE;       // Must be 0xB5 for Russian version. Discoverer: @dragonflylee
                _Data[6] = 0x16;       // Must be 0x60 for Russian version. Discoverer: @dragonflylee
                break;
            case NavicatLanguage::Portuguese:
                _Data[5] = 0xCD;       // Must be 0xCD for Portuguese version. Discoverer: @dragonflylee
                _Data[6] = 0x49;       // Must be 0x49 for Portuguese version. Discoverer: @dragonflylee
                break;
            default:
                break;
        }
    }

    void SerialNumberGenerator::SetLanguageSignature(BYTE LanguageSignature0, BYTE LanguageSignature1) noexcept {
        _Data[5] = LanguageSignature0;
        _Data[6] = LanguageSignature1;
    }

    void SerialNumberGenerator::SetProductSignature(NavicatProductType ProductType) noexcept {
        switch (ProductType) {
            case NavicatProductType::DataModeler:
                _Data[7] = 0x47;
                break;
            case NavicatProductType::Premium:
                _Data[7] = 0x65;
                break;
            case NavicatProductType::MySQL:
                _Data[7] = 0x68;
                break;
            case NavicatProductType::PostgreSQL:
                _Data[7] = 0x6C;
                break;
            case NavicatProductType::Oracle:
                _Data[7] = 0x70;
                break;
            case NavicatProductType::SQLServer:
                _Data[7] = 0x74;
                break;
            case NavicatProductType::SQLite:
                _Data[7] = 0x78;
                break;
            case NavicatProductType::MariaDB:
                _Data[7] = 0x7C;
                break;
            case NavicatProductType::MongoDB:
                _Data[7] = 0x80;
                break;
            case NavicatProductType::ReportViewer:
                _Data[7] = 0xb;
            default:
                break;
        }
    }

    void SerialNumberGenerator::SetProductSignature(BYTE ProductSignature) noexcept {
        _Data[7] = ProductSignature;
    }

    void SerialNumberGenerator::SetVersion(BYTE Version) {
        if (Version < 0x10) {
            _Data[8] = static_cast<BYTE>(Version << 4);
        } else {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Invalid version for Navicat."));
        }
    }

    void SerialNumberGenerator::Generate() {
        static const TCHAR EncodeTable[] = TEXT("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");

        RtlGenRandom(_Data + 2, 3);

        const_DES_cblock key = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };
        DES_key_schedule schedule;
        DES_set_key_unchecked(&key, &schedule);
        DES_ecb_encrypt(
            reinterpret_cast<const_DES_cblock*>(_Data + 2),
            reinterpret_cast<const_DES_cblock*>(_Data + 2),
            &schedule,
            DES_ENCRYPT
        );

        _SerialNumberShort.resize(16);

        _SerialNumberShort[0] = EncodeTable[_Data[0] >> 3];
        _SerialNumberShort[1] = EncodeTable[(_Data[0] & 0x07) << 2 | _Data[1] >> 6];
        _SerialNumberShort[2] = EncodeTable[_Data[1] >> 1 & 0x1F];
        _SerialNumberShort[3] = EncodeTable[(_Data[1] & 0x1) << 4 | _Data[2] >> 4];
        _SerialNumberShort[4] = EncodeTable[(_Data[2] & 0xF) << 1 | _Data[3] >> 7];
        _SerialNumberShort[5] = EncodeTable[_Data[3] >> 2 & 0x1F];
        _SerialNumberShort[6] = EncodeTable[_Data[3] << 3 & 0x1F | _Data[4] >> 5];
        _SerialNumberShort[7] = EncodeTable[_Data[4] & 0x1F];

        _SerialNumberShort[8] = EncodeTable[_Data[5] >> 3];
        _SerialNumberShort[9] = EncodeTable[(_Data[5] & 0x07) << 2 | _Data[6] >> 6];
        _SerialNumberShort[10] = EncodeTable[_Data[6] >> 1 & 0x1F];
        _SerialNumberShort[11] = EncodeTable[(_Data[6] & 0x1) << 4 | _Data[7] >> 4];
        _SerialNumberShort[12] = EncodeTable[(_Data[7] & 0xF) << 1 | _Data[8] >> 7];
        _SerialNumberShort[13] = EncodeTable[_Data[8] >> 2 & 0x1F];
        _SerialNumberShort[14] = EncodeTable[_Data[8] << 3 & 0x1F | _Data[9] >> 5];
        _SerialNumberShort[15] = EncodeTable[_Data[9] & 0x1F];

        _SerialNumberLong = std::xstring::format(
            TEXT("%.4s-%.4s-%.4s-%.4s"),
            _SerialNumberShort.c_str() + 0,
            _SerialNumberShort.c_str() + 4,
            _SerialNumberShort.c_str() + 8,
            _SerialNumberShort.c_str() + 12
        );
    }

    [[nodiscard]]
    const std::xstring& SerialNumberGenerator::GetSerialNumberShort() const noexcept {
        return _SerialNumberShort;
    }

    [[nodiscard]]
    const std::xstring& SerialNumberGenerator::GetSerialNumberLong() const noexcept {
        return _SerialNumberLong;
    }

    void SerialNumberGenerator::ShowInConsole() const {
        std::xcout << TEXT("[*] Serial number:") << std::endl;
        std::xcout << _SerialNumberLong << std::endl;
        std::xcout << std::endl;
    }
}

