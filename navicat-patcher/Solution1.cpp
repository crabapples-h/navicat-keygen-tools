#include "def.hpp"

namespace Patcher {

    const char* Solution1::Keywords[5] = {
        "D75125B70767B94145B47C1CB3C0755E"
        "7CCB8825C5DCE0C58ACF944E08280140"
        "9A02472FAFFD1CD77864BB821AE36766"
        "FEEDE6A24F12662954168BFA314BD950"
        "32B9D82445355ED7BC0B880887D650F5",

        "\xfe\xea\xbc\x01",

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
        "449B4E",

        "\x59\x08\x01\x00",

        "92933"
    };

    const int Solution1::KeywordsLength[5] = {
        160, 
        4, 
        742, 
        4,
        5
    };

    bool Solution1::CheckKey(RSACipher* cipher) const noexcept {
        BOOL bOk = FALSE;
        std::string RSAPublicKeyPEM;

        RSAPublicKeyPEM = 
            cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
        if (RSAPublicKeyPEM.empty()) {
            REPORT_ERROR("ERROR: cipher->ExportKeyString failed.");
            return false;
        }

        [](std::string& str, const std::string& OldSub, const std::string& NewSub) {
            std::string::size_type pos = 0;
            std::string::size_type srclen = OldSub.size();
            std::string::size_type dstlen = NewSub.size();

            while ((pos = str.find(OldSub, pos)) != std::string::npos) {
                str.replace(pos, srclen, NewSub);
                pos += dstlen;
            }
        } (RSAPublicKeyPEM, "\n", "\r\n");  // replace '\n' to '\r\n'

        std::string encrypted_pem_text = Helper::EncryptPublicKey(RSAPublicKeyPEM);

        if (encrypted_pem_text[160] > '9' || encrypted_pem_text[160] < '1') 
            return false;

        for (int i = 1; i < 8; ++i)
            if (encrypted_pem_text[160 + i] > '9' || encrypted_pem_text[160 + i] < '0') 
                return false;

        if (encrypted_pem_text[910] > '9' || encrypted_pem_text[910] < '1') 
            return false;

        for (int i = 1; i < 5; ++i)
            if (encrypted_pem_text[910 + i] > '9' || encrypted_pem_text[910 + i] < '0')
                return false;

        return true;
    }

    bool Solution1::FindPatchOffset() noexcept {
        PIMAGE_SECTION_HEADER textSection = nullptr;
        PIMAGE_SECTION_HEADER rdataSection = nullptr;

        uint8_t* pTargetFileView = pTargetFile->GetView<uint8_t>();
        off_t Offsets[5] = { -1, -1, -1, -1, -1 };

        textSection = Helper::ImageSectionHeader(pTargetFileView, ".text");
        if (textSection == nullptr) {
            // REPORT_ERROR("ERROR: Cannot find .text section.");
            return false;
        }

        rdataSection = Helper::ImageSectionHeader(pTargetFileView, ".rdata");
        if (textSection == nullptr) {
            // REPORT_ERROR("ERROR: Cannot find .rdata section.");
            return false;
        }

        // -------------------------
        // try to search Keywords[0]
        // -------------------------
        for (DWORD i = 0; i < rdataSection->SizeOfRawData; ++i) {
            if (memcmp(pTargetFileView + rdataSection->PointerToRawData + i, Keywords[0], KeywordsLength[0]) == 0) {
                Offsets[0] = rdataSection->PointerToRawData + i;
                break;
            }
        }

        if (Offsets[0] == -1) {
            // REPORT_ERROR("ERROR: Cannot find Keywords[0].");
            return false;
        }

        // -------------------------
        // try to search Keywords[2]
        // -------------------------
        for (DWORD i = 0; i < rdataSection->SizeOfRawData; ++i) {
            if (memcmp(pTargetFileView + rdataSection->PointerToRawData + i, Keywords[2], KeywordsLength[2]) == 0) {
                Offsets[2] = rdataSection->PointerToRawData + i;
                break;
            }
        }

        if (Offsets[2] == -1) {
            // REPORT_ERROR("ERROR: Cannot find Keywords[2].");
            return false;
        }

        // -------------------------
        // try to search Keywords[4]
        // -------------------------
        for (DWORD i = 0; i < rdataSection->SizeOfRawData; ++i) {
            if (memcmp((uint8_t*)pTargetFileView + rdataSection->PointerToRawData + i, Keywords[4], KeywordsLength[4]) == 0) {
                Offsets[4] = rdataSection->PointerToRawData + i;
                break;
            }
        }

        if (Offsets[4] == -1) {
            // REPORT_ERROR("ERROR: Cannot find Keywords[4].");
            return false;
        }

        // -------------------------
        // try to search Keywords[1] and Keywords[3]
        // -------------------------
        for (DWORD i = 0; i < textSection->SizeOfRawData; ++i) {
            if (memcmp(pTargetFileView + textSection->PointerToRawData + i, Keywords[1], KeywordsLength[1]) == 0) {

                // Keywords[3] must be close to Keywords[1]
                for (DWORD j = i - 64; j < i + 64; ++j) {
                    if (memcmp(pTargetFileView + textSection->PointerToRawData + j, Keywords[3], KeywordsLength[3]) == 0) {
                        Offsets[1] = textSection->PointerToRawData + i;
                        Offsets[3] = textSection->PointerToRawData + j;
                        break;
                    }
                }

                // Offsets[1] and Offsets[3] are set synchronously
                // so check Offsets[1] is enough
                if (Offsets[1] != -1)
                    break;
            }
        }

        if (Offsets[1] == -1) {
            // REPORT_ERROR("ERROR: Cannot find Keywords[1] and Keywords[3].");
            return false;
        }
        
        PatchOffsets[0] = Offsets[0];
        PatchOffsets[1] = Offsets[1];
        PatchOffsets[2] = Offsets[2];
        PatchOffsets[3] = Offsets[3];
        PatchOffsets[4] = Offsets[4];
        _tprintf_s(TEXT("MESSAGE: [Solution1] Keywords[0] has been found: offset = +0x%08lx.\n"), PatchOffsets[0]);
        _tprintf_s(TEXT("MESSAGE: [Solution1] Keywords[1] has been found: offset = +0x%08lx.\n"), PatchOffsets[1]);
        _tprintf_s(TEXT("MESSAGE: [Solution1] Keywords[2] has been found: offset = +0x%08lx.\n"), PatchOffsets[2]);
        _tprintf_s(TEXT("MESSAGE: [Solution1] Keywords[3] has been found: offset = +0x%08lx.\n"), PatchOffsets[3]);
        _tprintf_s(TEXT("MESSAGE: [Solution1] Keywords[4] has been found: offset = +0x%08lx.\n"), PatchOffsets[4]);

        return true;
    }

    bool Solution1::MakePatch(RSACipher* cipher) const {
        std::string RSAPublicKeyPEM;
        std::string encrypted_pem_pubkey;
        uint8_t* pTargetFileView = pTargetFile->GetView<uint8_t>();

        RSAPublicKeyPEM = cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
        if (RSAPublicKeyPEM.empty()) {
            REPORT_ERROR("ERROR: cipher->ExportKeyString failed.");
            return FALSE;
        }

        [](std::string& str, const std::string& OldSub, const std::string& NewSub) {
            std::string::size_type pos = 0;
            std::string::size_type srclen = OldSub.size();
            std::string::size_type dstlen = NewSub.size();

            while ((pos = str.find(OldSub, pos)) != std::string::npos) {
                str.replace(pos, srclen, NewSub);
                pos += dstlen;
            }
        } (RSAPublicKeyPEM, "\n", "\r\n");  // replace '\n' to '\r\n'

        encrypted_pem_pubkey = Helper::EncryptPublicKey(RSAPublicKeyPEM);

        // split encrypted_pem_pubkey to 5 part:    |160 chars|8 chars|742 chars|5 chars|5 chars|
        //                                                         |                |
        //                                                        \ /              \ /
        //                                                       imm1             imm3
        std::string encrypted_pem_pubkey0(encrypted_pem_pubkey.begin(), encrypted_pem_pubkey.begin() + 160);
        std::string encrypted_pem_pubkey1(encrypted_pem_pubkey.begin() + 160, encrypted_pem_pubkey.begin() + 160 + 8);
        std::string encrypted_pem_pubkey2(encrypted_pem_pubkey.begin() + 160 + 8, encrypted_pem_pubkey.begin() + 160 + 8 + 742);
        std::string encrypted_pem_pubkey3(encrypted_pem_pubkey.begin() + 160 + 8 + 742, encrypted_pem_pubkey.begin() + 160 + 8 + 742 + 5);
        std::string encrypted_pem_pubkey4(encrypted_pem_pubkey.begin() + 160 + 8 + 742 + 5, encrypted_pem_pubkey.end());
        uint32_t imm1 = std::stoul(encrypted_pem_pubkey1.c_str());
        uint32_t imm3 = std::stoul(encrypted_pem_pubkey3.c_str());

        PRINT_MESSAGE("//");
        PRINT_MESSAGE("// Begin Solution1");
        PRINT_MESSAGE("//");

        // ----------------------------------
        //     process PatchOffsets[0]
        // ----------------------------------
        _tprintf_s(TEXT("@+0x%08X\nPrevious:\n"), PatchOffsets[0]);
        Helper::PrintMemory(pTargetFileView + PatchOffsets[0],
                            pTargetFileView + PatchOffsets[0] + KeywordsLength[0],
                            pTargetFileView);
        memcpy(pTargetFileView + PatchOffsets[0], encrypted_pem_pubkey0.c_str(), KeywordsLength[0]);
        PRINT_MESSAGE("After:");
        Helper::PrintMemory(pTargetFileView + PatchOffsets[0],
                            pTargetFileView + PatchOffsets[0] + KeywordsLength[0],
                            pTargetFileView);
        PRINT_MESSAGE("");

        // ----------------------------------
        //     process PatchOffsets[1]
        // ----------------------------------
        _tprintf_s(TEXT("@+0x%08X\nPrevious:\n"), PatchOffsets[1]);
        Helper::PrintMemory(pTargetFileView + PatchOffsets[1],
                            pTargetFileView + PatchOffsets[1] + KeywordsLength[1],
                            pTargetFileView);
        memcpy(pTargetFileView + PatchOffsets[1], &imm1, KeywordsLength[1]);
        PRINT_MESSAGE("After:");
        Helper::PrintMemory(pTargetFileView + PatchOffsets[1],
                            pTargetFileView + PatchOffsets[1] + KeywordsLength[1],
                            pTargetFileView);
        PRINT_MESSAGE("");

        // ----------------------------------
        //     process PatchOffsets[2]
        // ----------------------------------
        _tprintf_s(TEXT("@+0x%08X\nPrevious:\n"), PatchOffsets[2]);
        Helper::PrintMemory(pTargetFileView + PatchOffsets[2],
                            pTargetFileView + PatchOffsets[2] + KeywordsLength[2],
                            pTargetFileView);
        memcpy(pTargetFileView + PatchOffsets[2], encrypted_pem_pubkey2.c_str(), KeywordsLength[2]);
        PRINT_MESSAGE("After:");
        Helper::PrintMemory(pTargetFileView + PatchOffsets[2],
                            pTargetFileView + PatchOffsets[2] + KeywordsLength[2],
                            pTargetFileView);
        PRINT_MESSAGE("");

        // ----------------------------------
        //     process PatchOffsets[3]
        // ----------------------------------
        _tprintf_s(TEXT("@+0x%08X\nPrevious:\n"), PatchOffsets[3]);
        Helper::PrintMemory(pTargetFileView + PatchOffsets[3],
                            pTargetFileView + PatchOffsets[3] + KeywordsLength[3],
                            pTargetFileView);
        memcpy(pTargetFileView + PatchOffsets[3], &imm3, KeywordsLength[3]);
        PRINT_MESSAGE("After:");
        Helper::PrintMemory(pTargetFileView + PatchOffsets[3],
                            pTargetFileView + PatchOffsets[3] + KeywordsLength[3],
                            pTargetFileView);
        PRINT_MESSAGE("");

        // ----------------------------------
        //     process PatchOffsets[4]
        // ----------------------------------
        _tprintf_s(TEXT("@+0x%08X\nPrevious:\n"), PatchOffsets[4]);
        Helper::PrintMemory(pTargetFileView + PatchOffsets[4],
                            pTargetFileView + PatchOffsets[4] + KeywordsLength[4],
                            pTargetFileView);
        memcpy(pTargetFileView + PatchOffsets[4], encrypted_pem_pubkey4.c_str(), KeywordsLength[4]);
        PRINT_MESSAGE("After:");
        Helper::PrintMemory(pTargetFileView + PatchOffsets[4],
                            pTargetFileView + PatchOffsets[4] + KeywordsLength[4],
                            pTargetFileView);
        PRINT_MESSAGE("");
        return TRUE;
    }

}

