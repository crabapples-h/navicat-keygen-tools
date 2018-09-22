#pragma once
#include "RSACipher.hpp"
#include <openssl/des.h>
#include <string>
#include <random>

class NavicatKeygen {
public:
    enum class Language {
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

    enum class Product {
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
private:
    std::random_device rand_dev;
    std::default_random_engine rand_eng;
    std::uniform_int_distribution<int> rand;
    uint8_t data[10];

    void DoEncrypt() {
        const_DES_cblock DESKey = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };
        DES_key_schedule schedule;
        DES_cblock enc_data;

        DES_set_key_unchecked(&DESKey, &schedule);
        DES_ecb_encrypt(reinterpret_cast<const_DES_cblock*>(data + 2),
                        &enc_data,
                        &schedule,
                        DES_ENCRYPT);
        memcpy(data + 2, enc_data, sizeof(enc_data));
    }

public:

    NavicatKeygen() : rand_eng(rand_dev()), rand(0, UINT8_MAX), data() {
        data[0] = 0x68;
        data[1] = 0x2A;
    }

    void SetLanguageSignature(Language _language) {
        switch (_language) {
        case Language::English:
            data[5] = 0xAC;       // Must be 0xAC for English version.
            data[6] = 0x88;       // Must be 0x88 for English version.
            break;
        case Language::SimplifiedChinese:
            data[5] = 0xCE;       // Must be 0xCE for Simplified Chinese version.
            data[6] = 0x32;       // Must be 0x32 for Simplified Chinese version.
            break;
        case Language::TraditionalChinese:
            data[5] = 0xAA;       // Must be 0xAA for Traditional Chinese version.
            data[6] = 0x99;       // Must be 0x99 for Traditional Chinese version.
            break;
        case Language::Japanese:
            data[5] = 0xAD;       // Must be 0xAD for Japanese version. Discoverer: @dragonflylee
            data[6] = 0x82;       // Must be 0x82 for Japanese version. Discoverer: @dragonflylee
            break;
        case Language::Polish:
            data[5] = 0xBB;       // Must be 0xBB for Polish version. Discoverer: @dragonflylee
            data[6] = 0x55;       // Must be 0x55 for Polish version. Discoverer: @dragonflylee
            break;
        case Language::Spanish:
            data[5] = 0xAE;       // Must be 0xAE for Spanish version. Discoverer: @dragonflylee
            data[6] = 0x10;       // Must be 0x10 for Spanish version. Discoverer: @dragonflylee
            break;
        case Language::French:
            data[5] = 0xFA;       // Must be 0xFA for French version. Discoverer: @Deltafox79
            data[6] = 0x20;       // Must be 0x20 for French version. Discoverer: @Deltafox79
            break;
        case Language::German:
            data[5] = 0xB1;       // Must be 0xB1 for German version. Discoverer: @dragonflylee
            data[6] = 0x60;       // Must be 0x60 for German version. Discoverer: @dragonflylee
            break;
        case Language::Korean:
            data[5] = 0xB5;       // Must be 0xB5 for Korean version. Discoverer: @dragonflylee
            data[6] = 0x60;       // Must be 0x60 for Korean version. Discoverer: @dragonflylee
            break;
        case Language::Russian:
            data[5] = 0xEE;       // Must be 0xB5 for Russian version. Discoverer: @dragonflylee
            data[6] = 0x16;       // Must be 0x60 for Russian version. Discoverer: @dragonflylee
            break;
        case Language::Portuguese:
            data[5] = 0xCD;       // Must be 0xCD for Portuguese version. Discoverer: @dragonflylee
            data[6] = 0x49;       // Must be 0x49 for Portuguese version. Discoverer: @dragonflylee
            break;
        default:
            break;
        }
    }

    void SetLanguageSignature(uint8_t value0, uint8_t value1) {
        data[5] = value0;
        data[6] = value1;
    }

    void SetProductSignature(Product _product) {
        switch (_product) {
        case Product::DataModeler:
            data[7] = 0x47;
            break;
        case Product::Premium:
            data[7] = 0x65;
            break;
        case Product::MySQL:
            data[7] = 0x68;
            break;
        case Product::PostgreSQL:
            data[7] = 0x6C;
            break;
        case Product::Oracle:
            data[7] = 0x70;
            break;
        case Product::SQLServer:
            data[7] = 0x74;
            break;
        case Product::SQLite:
            data[7] = 0x78;
            break;
        case Product::MariaDB:
            data[7] = 0x7C;
            break;
        case Product::MongoDB:
            data[7] = 0x80;
            break;
        case Product::ReportViewer:
            data[7] = 0xb;
        default:
            break;
        }
    }

    void SetProductSignature(uint8_t value) {
        data[7] = value;
    }

    void SetVersion(uint8_t version) {
        data[8] = version << 4;
    }

    void Generate() {
        data[2] = rand(rand_eng);
        data[3] = rand(rand_eng);
        data[4] = rand(rand_eng);
        data[9] = 0x32;
        DoEncrypt();
    }

    std::string GetKey() const {
        std::string Key;
        const char EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        Key.resize(16);
        Key[0] = EncodeTable[data[0] >> 3];
        Key[1] = EncodeTable[(data[0] & 0x07) << 2 | data[1] >> 6];
        Key[2] = EncodeTable[data[1] >> 1 & 0x1F];
        Key[3] = EncodeTable[(data[1] & 0x1) << 4 | data[2] >> 4];
        Key[4] = EncodeTable[(data[2] & 0xF) << 1 | data[3] >> 7];
        Key[5] = EncodeTable[data[3] >> 2 & 0x1F];
        Key[6] = EncodeTable[data[3] << 3 & 0x1F | data[4] >> 5];
        Key[7] = EncodeTable[data[4] & 0x1F];

        Key[8] = EncodeTable[data[5] >> 3];
        Key[9] = EncodeTable[(data[5] & 0x07) << 2 | data[6] >> 6];
        Key[10] = EncodeTable[data[6] >> 1 & 0x1F];
        Key[11] = EncodeTable[(data[6] & 0x1) << 4 | data[7] >> 4];
        Key[12] = EncodeTable[(data[7] & 0xF) << 1 | data[8] >> 7];
        Key[13] = EncodeTable[data[8] >> 2 & 0x1F];
        Key[14] = EncodeTable[data[8] << 3 & 0x1F | data[9] >> 5];
        Key[15] = EncodeTable[data[9] & 0x1F];

        return Key;
    }

    std::string GetFormatedKey() const {
        std::string Key = GetKey();
        auto ptr = Key.begin() + 4;

        ptr = Key.insert(ptr, '-');
        ptr++;
        ptr += 4;
        ptr = Key.insert(ptr, '-');
        ptr++;
        ptr += 4;
        Key.insert(ptr, '-');

        return Key;
    }

};
