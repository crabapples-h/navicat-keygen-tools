#include "def.hpp"

namespace Patcher {

    const char Solution2::KeywordsMeta[KeywordsCount + 1] =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I"
        "qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv"
        "a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF"
        "R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2"
        "WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt"
        "YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ"
        "awIDAQAB";

    uint8_t Solution2::Keywords[KeywordsCount][5];

#if defined(_M_X64)

    void Solution2::BuildKeywords() noexcept {
        for (size_t i = 0; i < KeywordsCount; ++i) {
            Keywords[i][0] = 0x83;      // Keywords[i] = asm('xor eax, KeywordsMeta[i]') + 
            Keywords[i][1] = 0xf0;
            Keywords[i][2] = KeywordsMeta[i];
            Keywords[i][3] = 0x88;      //               asm_prefix('mov byte ptr ds:xxxxxxxxxxxxxxxx, al')
            Keywords[i][4] = 0x05;
        }
    }

    bool Solution2::FindPatchOffset() noexcept {
        PIMAGE_SECTION_HEADER textSection = nullptr;
        uint8_t* pTargetFileView = pTargetFile->GetView<uint8_t>();
        uint8_t* ptextSectionData = nullptr;
        off_t Offsets[KeywordsCount];
        memset(Offsets, -1, sizeof(Offsets));

        textSection = Helper::ImageSectionHeader(pTargetFileView, ".text");
        if (textSection == nullptr)
            return false;
        ptextSectionData = pTargetFileView + textSection->PointerToRawData;

        BuildKeywords();

        // Find offsets
        {
            size_t FirstKeywordCounter = 0;
            uint32_t Hints[9];
            DWORD PossibleRangeStart = 0xffffffff;
            DWORD PossibleRangeEnd;
            for (DWORD i = 0; i < textSection->SizeOfRawData; ++i) {
                if (memcmp(ptextSectionData + i, Keywords[0], sizeof(Keywords[0])) == 0) {
                    Hints[FirstKeywordCounter++] =
                        *reinterpret_cast<uint32_t*>(ptextSectionData + i + sizeof(Keywords[0])) +
                        i + sizeof(Keywords[0]) + sizeof(uint32_t);
                    if (i < PossibleRangeStart)
                        PossibleRangeStart = i;
                }
            }

            PossibleRangeStart -= 0x1000;
            PossibleRangeEnd = PossibleRangeStart + 0x100000;

            // Keywords[0] should occur 9 times. 
            // Because there's only 9 'M' chars in `KeywordsMeta`.
            if (FirstKeywordCounter != 9)
                return false;

            Helper::QuickSort(Hints, 0, _countof(Hints));

            // assert
            // if not satisfied, refuse to patch
            if (Hints[8] - Hints[0] != 0x18360F8F8 - 0x18360F7D0)
                return false;
            
            for (size_t i = 0; i < KeywordsCount; ++i) {
                if (Offsets[i] != -1)
                    continue;

                for (DWORD j = PossibleRangeStart; j < PossibleRangeEnd; ++j) {
                    if (memcmp(ptextSectionData + j, Keywords[i], sizeof(Keywords[i])) == 0) {
                        off_t index =
                            *reinterpret_cast<uint32_t*>(ptextSectionData + j + sizeof(Keywords[i])) +
                            j + sizeof(Keywords[i]) + sizeof(uint32_t) - Hints[0];

                        if (0 <= index && index < KeywordsCount && KeywordsMeta[index] == KeywordsMeta[i]) {
                            Offsets[index] = textSection->PointerToRawData + j;
                        }
                    }
                }

                // if not found, refuse to patch
                if (Offsets[i] == -1)
                    return false;
            }
        }
        
        static_assert(sizeof(PatchOffsets) == sizeof(Offsets), "static_assert failure!");
        memcpy(PatchOffsets, Offsets, sizeof(PatchOffsets));

        for (size_t i = 0; i < KeywordsCount; ++i)
            _tprintf_s(TEXT("MESSAGE: [Solution2] Keywords[%zu] has been found: offset = +0x%08lx.\n"), 
                       i, PatchOffsets[i]);

        return true;
    }

#else

    void Solution2::BuildKeywords() noexcept {
        for (size_t i = 0; i < KeywordsCount; ++i) {
            switch (i % 3) {
                case 0:
                    Keywords[i][0] = 0x83;      // Keywords[i] = asm('xor edx, KeywordsMeta[i]') + 
                    Keywords[i][1] = 0xf2;
                    Keywords[i][2] = KeywordsMeta[i];
                    Keywords[i][3] = 0x88;      //               asm_prefix('mov byte ptr ds:xxxxxxxx, dl')
                    Keywords[i][4] = 0x15;
                    break;
                case 1:
                    Keywords[i][0] = 0x83;      // Keywords[i] = asm('xor eax, KeywordsMeta[i]') + 
                    Keywords[i][1] = 0xf0;
                    Keywords[i][2] = KeywordsMeta[i];
                    Keywords[i][3] = 0xa2;      //               asm_prefix('mov byte ptr ds:xxxxxxxx, al')
                    break;
                default:
                    Keywords[i][0] = 0x83;      // Keywords[i] = asm('xor ecx, KeywordsMeta[i]') + 
                    Keywords[i][1] = 0xf1;
                    Keywords[i][2] = KeywordsMeta[i];
                    Keywords[i][3] = 0x88;      //               asm_prefix('mov byte ptr ds:xxxxxxxx, cl')
                    Keywords[i][4] = 0x0D;
                    break;
            }
            
        }
    }

    bool Solution2::FindPatchOffset() noexcept {
        PIMAGE_SECTION_HEADER textSection = nullptr;
        uint8_t* pTargetFileView = pTargetFile->GetView<uint8_t>();
        uint8_t* ptextSectionData = nullptr;
        off_t Offsets[KeywordsCount];
        memset(Offsets, -1, sizeof(Offsets));

        textSection = Helper::ImageSectionHeader(pTargetFileView, ".text");
        if (textSection == nullptr)
            return false;
        ptextSectionData = pTargetFileView + textSection->PointerToRawData;

        BuildKeywords();

        // Find offsets
        {
            size_t FirstKeywordCounter = 0;
            uint32_t Hints[3];
            DWORD PossibleRangeStart = 0xffffffff;
            DWORD PossibleRangeEnd;
            for (DWORD i = 0; i < textSection->SizeOfRawData; ++i) {
                if (memcmp(ptextSectionData + i, Keywords[0], sizeof(Keywords[0])) == 0) {
                    Hints[FirstKeywordCounter++] =
                        *reinterpret_cast<uint32_t*>(ptextSectionData + i + sizeof(Keywords[0]));
                    if (i < PossibleRangeStart)
                        PossibleRangeStart = i;
                }
            }

            PossibleRangeStart -= 0x1000;
            PossibleRangeEnd = PossibleRangeStart + 0x100000;

            // Keywords[0] should occur 3 times. 
            if (FirstKeywordCounter != 3)
                return false;

            Helper::QuickSort(Hints, 0, _countof(Hints));

            // assert
            // if not satisfied, refuse to patch
            if (Hints[2] - Hints[0] != 0x127382BE - 0x12738210)
                return false;

            for (size_t i = 0; i < KeywordsCount; ++i) {
                uint8_t CurrentKeyword[9];
                size_t CurrentKeywordSize = i % 3 == 1 ? 4 : 5;
                memcpy(CurrentKeyword, Keywords[i], CurrentKeywordSize);
                *reinterpret_cast<uint32_t*>(CurrentKeyword + CurrentKeywordSize) = Hints[0] + i;
                CurrentKeywordSize += sizeof(uint32_t);

                for (DWORD j = PossibleRangeStart; j < PossibleRangeEnd; ++j) {
                    if (memcmp(ptextSectionData + j, CurrentKeyword, CurrentKeywordSize) == 0) {
                        Offsets[i] = textSection->PointerToRawData + j;
                        break;
                    }
                }

                // if not found, refuse to patch
                if (Offsets[i] == -1)
                    return false;
            }
        }

        static_assert(sizeof(PatchOffsets) == sizeof(Offsets), "static_assert failure!");
        memcpy(PatchOffsets, Offsets, sizeof(PatchOffsets));

        for (size_t i = 0; i < KeywordsCount; ++i)
            _tprintf_s(TEXT("MESSAGE: [Solution2] Keywords[%zu] has been found: offset = +0x%08lx.\n"),
                       i, PatchOffsets[i]);

        return true;
    }

#endif

    bool Solution2::MakePatch(RSACipher* cipher) const {
        std::string RSAPublicKeyPEM;
        uint8_t* pTargetFileView = pTargetFile->GetView<uint8_t>();

        RSAPublicKeyPEM = cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
        if (RSAPublicKeyPEM.empty()) {
            REPORT_ERROR("ERROR: cipher->ExportKeyString failed.");
            return false;
        }

        RSAPublicKeyPEM.erase(RSAPublicKeyPEM.find("-----BEGIN PUBLIC KEY-----"), 26);
        RSAPublicKeyPEM.erase(RSAPublicKeyPEM.find("-----END PUBLIC KEY-----"), 24);
        {
            std::string::size_type pos = 0;
            while ((pos = RSAPublicKeyPEM.find("\n", pos)) != std::string::npos) {
                RSAPublicKeyPEM.erase(pos, 1);
            }
        }

        if (RSAPublicKeyPEM.length() != KeywordsCount) {
            REPORT_ERROR("ERROR: Public key length does not match.");
            return false;
        }

        PRINT_MESSAGE("//");
        PRINT_MESSAGE("// Begin Solution2");
        PRINT_MESSAGE("//");
        for (size_t i = 0; i < KeywordsCount; ++i) {
            _tprintf_s(TEXT("@+0x%08X: %02X %02X %02X --> "), 
                       PatchOffsets[i],
                       pTargetFileView[PatchOffsets[i]],
                       pTargetFileView[PatchOffsets[i] + 1],
                       pTargetFileView[PatchOffsets[i] + 2]);
            pTargetFileView[PatchOffsets[i] + 2] = RSAPublicKeyPEM[i];
            _tprintf_s(TEXT("%02X %02X %02X\n"),
                       pTargetFileView[PatchOffsets[i]],
                       pTargetFileView[PatchOffsets[i] + 1],
                       pTargetFileView[PatchOffsets[i] + 2]);
        }

        PRINT_MESSAGE("");
        return true;
    }
}
