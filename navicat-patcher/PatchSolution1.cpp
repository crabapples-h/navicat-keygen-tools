#include "PatchSolutions.hpp"
#include "NavicatCrypto.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\PatchSolution1.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    static Navicat11Crypto g_NavicatCipher = Navicat11Crypto("23970790", 8);

    const char PatchSolution1::Keyword0[160 + 1] =
        "D75125B70767B94145B47C1CB3C0755E"
        "7CCB8825C5DCE0C58ACF944E08280140"
        "9A02472FAFFD1CD77864BB821AE36766"
        "FEEDE6A24F12662954168BFA314BD950"
        "32B9D82445355ED7BC0B880887D650F5";

    const char PatchSolution1::Keyword1[4 + 1] =
        "\xfe\xea\xbc\x01";

    const char PatchSolution1::Keyword2[742 + 1] =
        "E1CED09B9C2186BF71A70C0FE2F1E0AE"
        "F3BD6B75277AAB20DFAF3D110F75912B"
        "FB63AC50EC4C48689D1502715243A79F"
        "39FF2DE2BF15CE438FF885745ED54573"
        "850E8A9F40EE2FF505EB7476F95ADB78"
        "3B28CA374FAC4632892AB82FB3BF4715"
        "FCFE6E82D03731FC3762B6AAC3DF1C3B"
        "C646FE9CD3C62663A97EE72DB932A301"
        "312B4A7633100C8CC357262C39A2B3A6"
        "4B224F5276D5EDBDF0804DC3AC4B8351"
        "62BB1969EAEBADC43D2511D6E0239287"
        "81B167A48273B953378D3D2080CC0677"
        "7E8A2364F0234B81064C5C739A8DA28D"
        "C5889072BF37685CBC94C2D31D0179AD"
        "86D8E3AA8090D4F0B281BE37E0143746"
        "E6049CCC06899401264FA471C016A96C"
        "79815B55BBC26B43052609D9D175FBCD"
        "E455392F10E51EC162F51CF732E6BB39"
        "1F56BBFD8D957DF3D4C55B71CEFD54B1"
        "9C16D458757373E698D7E693A8FC3981"
        "5A8BF03BA05EA8C8778D38F9873D62B4"
        "460F41ACF997C30E7C3AF025FA171B5F"
        "5AD4D6B15E95C27F6B35AD61875E5505"
        "449B4E";

    const char PatchSolution1::Keyword3[4 + 1] =
        "\x59\x08\x01\x00";

    const char PatchSolution1::Keyword4[5 + 1] =
        "92933";

    [[nodiscard]]
    bool PatchSolution1::FindPatchOffset() noexcept {
        try {
            PIMAGE_SECTION_HEADER SectionHeader_text = _Image.ImageSectionHeaderByName(".text");
            PIMAGE_SECTION_HEADER SectionHeader_rdata = _Image.ImageSectionHeaderByName(".rdata");
            const uint8_t* pbPatch[_countof(_PatchOffset)] = {};

            pbPatch[0] = _Image.SearchSection<const uint8_t*>(SectionHeader_rdata, [](const uint8_t* p) {
                __try {
                    return memcmp(p, Keyword0, sizeof(Keyword0)) == 0;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            });

            pbPatch[2] = _Image.SearchSection<const uint8_t*>(SectionHeader_rdata, [](const uint8_t* p) {
                __try {
                    return memcmp(p, Keyword2, sizeof(Keyword2)) == 0;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            });

            pbPatch[4] = _Image.SearchSection<const uint8_t*>(SectionHeader_rdata, [](const uint8_t* p) {
                __try {
                    return memcmp(p, Keyword4, sizeof(Keyword4)) == 0;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            });

            pbPatch[1] = _Image.SearchSection<const uint8_t*>(SectionHeader_text, [&pbPatch](const uint8_t* p) {
                __try {
                    if (memcmp(p, Keyword1, literal_length(Keyword1)) == 0) {
                        // Keyword3 must be close to Keyword1
                        for (auto j = p - 64; j < p + 64; ++j) {
                            if (memcmp(j, Keyword3, literal_length(Keyword3)) == 0) {
                                pbPatch[3] = j;
                                return true;
                            }
                        }
                    }

                    return false;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            });

            for (size_t i = 0; i < _countof(_PatchOffset); ++i) {
                _PatchOffset[i] = _Image.PointerToFileOffset(pbPatch[i]);
            }

            _PatchSize[0] = literal_length(Keyword0);
            while (pbPatch[0][_PatchSize[0] + 1] == 0 && _PatchSize[0] < literal_length(Keyword0) + literal_length("29158142") - 1) {
                ++_PatchSize[0];
            }

            _PatchSize[1] = sizeof(uint32_t);

            _PatchSize[2] = literal_length(Keyword2);
            while (pbPatch[2][_PatchSize[2] + 1] == 0 && _PatchSize[2] < literal_length(Keyword2) + literal_length("67673") - 1) {
                ++_PatchSize[2];
            }

            _PatchSize[3] = sizeof(uint32_t);

            _PatchSize[4] = literal_length(Keyword4);

            LOG_SUCCESS(0, "PatchSolution1 ...... Ready to apply");
            LOG_HINT(4, "[0] Patch offset = +0x%.8zx", _PatchOffset[0]);
            LOG_HINT(4, "[1] Patch offset = +0x%.8zx", _PatchOffset[1]);
            LOG_HINT(4, "[2] Patch offset = +0x%.8zx", _PatchOffset[2]);
            LOG_HINT(4, "[3] Patch offset = +0x%.8zx", _PatchOffset[3]);
            LOG_HINT(4, "[4] Patch offset = +0x%.8zx", _PatchOffset[4]);

            return true;
        } catch (nkg::Exception&) {
            for (size_t i = 0; i < _countof(_PatchOffset); ++i) {
                _PatchOffset[i] = InvalidOffset;
                _PatchSize[i] = 0;
            }

            LOG_FAILURE(0, "PatchSolution1 ...... Omitted");

            return false;
        }
    }

    [[nodiscard]]
    bool PatchSolution1::CheckKey(const RSACipher& Cipher) const noexcept {
        if (_PatchSize[0] && _PatchSize[1] && _PatchSize[2] && _PatchSize[3] && _PatchSize[4]) {
            auto szPublicKey = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();
            for (auto i = szPublicKey.find("\n"); i != std::string::npos; i = szPublicKey.find("\n", i + 2)) {
                szPublicKey.replace(i, 1, "\r\n");
            }

            auto szPublicKeyEncrypted = g_NavicatCipher.EncryptString(szPublicKey);

            if (szPublicKeyEncrypted.length() != 920) {
                return false;
            }

            // we require the chars in [p1, p2) of szPublicKeyEncrypted must be number chars
            size_t p1, p2;

            p1 = _PatchSize[0];
            p2 = literal_length(Keyword0) + literal_length("29158142");

            if (('1' <= szPublicKeyEncrypted[p1] && szPublicKeyEncrypted[p1] <= '9') == false) {
                return false;
            }

            for (size_t i = p1 + 1; i < p2; ++i) {
                if (('0' <= szPublicKeyEncrypted[i] && szPublicKeyEncrypted[i] <= '9') == false) {
                    return false;
                }
            }

            // we require the chars in [p1, p2) of szPublicKeyEncrypted must be number chars

            p1 = literal_length(Keyword0) + literal_length("29158142") + _PatchSize[2];
            p2 = literal_length(Keyword0) + literal_length("29158142") + literal_length(Keyword2) + literal_length("67673");

            if (('1' <= szPublicKeyEncrypted[p1] && szPublicKeyEncrypted[p1] <= '9') == false) {
                return false;
            }

            for (size_t i = p1 + 1; i < p2; ++i) {
                if (('0' <= szPublicKeyEncrypted[i] && szPublicKeyEncrypted[i] <= '9') == false) {
                    return false;
                }
            }

            return true;
        } else {
            return false;
        }
    }

    void PatchSolution1::MakePatch(const RSACipher& Cipher) const {
        if (_PatchSize[0] && _PatchSize[1] && _PatchSize[2] && _PatchSize[3] && _PatchSize[4]) {
            auto szPublicKey = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();
            for (auto i = szPublicKey.find("\n"); i != std::string::npos; i = szPublicKey.find("\n", i + 2)) {
                szPublicKey.replace(i, 1, "\r\n");
            }

            auto szPublicKeyEncrypted = g_NavicatCipher.EncryptString(szPublicKey);

            //
            //                                          p0        p1      p2        p3      p4      p5
            // Original encrypted public key layout:    |160 chars|8 chars|742 chars|5 chars|5 chars|
            //                                                       |                  |
            //                                                       V                  V
            //                                                    ImmValue1          ImmValue3
            size_t p0, p1, p2, p3, p4, p5;
            p0 = 0;
            p1 = _PatchSize[0];
            p2 = literal_length(Keyword0) + literal_length("29158142");
            p3 = literal_length(Keyword0) + literal_length("29158142") + _PatchSize[2];
            p4 = literal_length(Keyword0) + literal_length("29158142") + literal_length(Keyword2) + literal_length("67673");
            p5 = literal_length(Keyword0) + literal_length("29158142") + literal_length(Keyword2) + literal_length("67673") + literal_length(Keyword4);

            if (szPublicKeyEncrypted.length() != 920) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("szPublicKeyEncrypted.length() != 920"));
            }

            std::string EncryptedPEM0(szPublicKeyEncrypted.begin() + p0, szPublicKeyEncrypted.begin() + p1);
            std::string EncryptedPEM1(szPublicKeyEncrypted.begin() + p1, szPublicKeyEncrypted.begin() + p2);
            std::string EncryptedPEM2(szPublicKeyEncrypted.begin() + p2, szPublicKeyEncrypted.begin() + p3);
            std::string EncryptedPEM3(szPublicKeyEncrypted.begin() + p3, szPublicKeyEncrypted.begin() + p4);
            std::string EncryptedPEM4(szPublicKeyEncrypted.begin() + p4, szPublicKeyEncrypted.begin() + p5);
            uint32_t ImmValue1 = std::stoul(EncryptedPEM1.c_str());
            uint32_t ImmValue3 = std::stoul(EncryptedPEM3.c_str());

            uint8_t* pbPatch[_countof(_PatchOffset)] = {};
            for (size_t i = 0; i < _countof(_PatchOffset); ++i) {
                pbPatch[i] = _Image.FileOffsetToPointer<uint8_t*>(_PatchOffset[i]);
            }

            _putts(TEXT("*******************************************************"));
            _putts(TEXT("*                   PatchSolution1                    *"));
            _putts(TEXT("*******************************************************"));

            // ----------------------------------
            //     process PatchOffsets[0]
            // ----------------------------------
            LOG_HINT(0, "Previous:");
            PrintMemory(pbPatch[0], _PatchSize[0], _Image.ImageBase());

            memcpy(pbPatch[0], EncryptedPEM0.data(), _PatchSize[0]);

            LOG_HINT(0, "After:");
            PrintMemory(pbPatch[0], _PatchSize[0], _Image.ImageBase());

            _putts(TEXT(""));

            // ----------------------------------
            //     process PatchOffsets[1]
            // ----------------------------------
            LOG_HINT(0, "Previous:");
            PrintMemory(pbPatch[1], _PatchSize[1], _Image.ImageBase());

            memcpy(pbPatch[1], &ImmValue1, _PatchSize[1]);

            LOG_HINT(0, "After:");
            PrintMemory(pbPatch[1], _PatchSize[1], _Image.ImageBase());

            _putts(TEXT(""));

            // ----------------------------------
            //     process PatchOffsets[2]
            // ----------------------------------
            LOG_HINT(0, "Previous:");
            PrintMemory(pbPatch[2], _PatchSize[2], _Image.ImageBase());

            memcpy(pbPatch[2], EncryptedPEM2.data(), _PatchSize[2]);

            LOG_HINT(0, "After:");
            PrintMemory(pbPatch[2], _PatchSize[2], _Image.ImageBase());

            _putts(TEXT(""));

            // ----------------------------------
            //     process PatchOffsets[3]
            // ----------------------------------
            LOG_HINT(0, "Previous:");
            PrintMemory(pbPatch[3], _PatchSize[3], _Image.ImageBase());

            memcpy(pbPatch[3], &ImmValue3, _PatchSize[3]);

            LOG_HINT(0, "After:");
            PrintMemory(pbPatch[3], _PatchSize[3], _Image.ImageBase());

            _putts(TEXT(""));

            // ----------------------------------
            //     process PatchOffsets[4]
            // ----------------------------------
            LOG_HINT(0, "Previous:");
            PrintMemory(pbPatch[4], _PatchSize[4], _Image.ImageBase());

            memcpy(pbPatch[4], EncryptedPEM4.data(), _PatchSize[4]);

            LOG_HINT(0, "After:");
            PrintMemory(pbPatch[4], _PatchSize[4], _Image.ImageBase());

            _putts(TEXT(""));
        } else {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PatchSolution1 has not been ready yet."));
        }
    }
}

