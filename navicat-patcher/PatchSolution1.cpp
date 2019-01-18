#include "PatchSolution.hpp"
#include <tchar.h>
#include "Helper.hpp"

#undef __BASE_FILE__
#define __BASE_FILE__ "PatchSolution1.cpp"

const char* PatchSolution1::Keywords[5] = {
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

const size_t PatchSolution1::KeywordsLength[5] = {
    160,
    4,
    742,
    4,
    5
};

bool PatchSolution1::CheckKey(RSACipher* cipher) const {
    BOOL bOk = FALSE;

    std::string RSAPublicKeyPEM =
        cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
    Helper::ReplaceSubString(RSAPublicKeyPEM, "\n", "\r\n");
    std::string EncryptedPem = 
        Helper::NavicatCipher.EncryptString(RSAPublicKeyPEM);

    if (EncryptedPem.length() != 920)
        return false;

    if (EncryptedPem[160] > '9' || EncryptedPem[160] < '1')
        return false;

    for (int i = 1; i < 8; ++i)
        if (EncryptedPem[160 + i] > '9' || EncryptedPem[160 + i] < '0')
            return false;

    if (EncryptedPem[910] > '9' || EncryptedPem[910] < '1')
        return false;

    for (int i = 1; i < 5; ++i)
        if (EncryptedPem[910 + i] > '9' || EncryptedPem[910 + i] < '0')
            return false;

    return true;
}

bool PatchSolution1::FindPatchOffset() noexcept {
    PIMAGE_SECTION_HEADER textSectionHeader = _TargetFile.GetSectionHeader(".text");
    PIMAGE_SECTION_HEADER rdataSectionHeader = _TargetFile.GetSectionHeader(".rdata");
    uint8_t* PtrToSectiontext = _TargetFile.GetSectionView<uint8_t>(".text");
    uint8_t* PtrToSectionrdata = _TargetFile.GetSectionView<uint8_t>(".rdata");
    off_t Offsets[5] = { -1, -1, -1, -1, -1 };

    if (textSectionHeader == nullptr)
        return false;
    if (rdataSectionHeader == nullptr)
        return false;

    // -------------------------
    // try to search Keywords[0]
    // -------------------------
    for (DWORD i = 0; i < rdataSectionHeader->SizeOfRawData; ++i) {
        if (memcmp(PtrToSectionrdata + i, Keywords[0], KeywordsLength[0]) == 0) {
            Offsets[0] = rdataSectionHeader->PointerToRawData + i;
            break;
        }
    }

    if (Offsets[0] == -1)
        return false;

    // -------------------------
    // try to search Keywords[2]
    // -------------------------
    for (DWORD i = 0; i < rdataSectionHeader->SizeOfRawData; ++i) {
        if (memcmp(PtrToSectionrdata + i, Keywords[2], KeywordsLength[2]) == 0) {
            Offsets[2] = rdataSectionHeader->PointerToRawData + i;
            break;
        }
    }

    if (Offsets[2] == -1)
        return false;

    // -------------------------
    // try to search Keywords[4]
    // -------------------------
    for (DWORD i = 0; i < rdataSectionHeader->SizeOfRawData; ++i) {
        if (memcmp(PtrToSectionrdata + i, Keywords[4], KeywordsLength[4]) == 0) {
            Offsets[4] = rdataSectionHeader->PointerToRawData + i;
            break;
        }
    }

    if (Offsets[4] == -1)
        return false;

    // -------------------------
    // try to search Keywords[1] and Keywords[3]
    // -------------------------
    for (DWORD i = 0; i < textSectionHeader->SizeOfRawData; ++i) {
        if (memcmp(PtrToSectiontext + i, Keywords[1], KeywordsLength[1]) == 0) {

            // Keywords[3] must be close to Keywords[1]
            for (DWORD j = i - 64; j < i + 64; ++j) {
                if (memcmp(PtrToSectiontext + j, Keywords[3], KeywordsLength[3]) == 0) {
                    Offsets[1] = textSectionHeader->PointerToRawData + i;
                    Offsets[3] = textSectionHeader->PointerToRawData + j;
                    break;
                }
            }

            // Offsets[1] and Offsets[3] are set synchronously
            // so check Offsets[1] is enough
            if (Offsets[1] != -1)
                break;
        }
    }

    if (Offsets[1] == -1)
        return false;

    PatchOffsets[0] = Offsets[0];
    PatchOffsets[1] = Offsets[1];
    PatchOffsets[2] = Offsets[2];
    PatchOffsets[3] = Offsets[3];
    PatchOffsets[4] = Offsets[4];
    _tprintf_s(TEXT("MESSAGE: [PatchSolution1] Keywords[0] has been found: offset = +0x%08lx.\n"), PatchOffsets[0]);
    _tprintf_s(TEXT("MESSAGE: [PatchSolution1] Keywords[1] has been found: offset = +0x%08lx.\n"), PatchOffsets[1]);
    _tprintf_s(TEXT("MESSAGE: [PatchSolution1] Keywords[2] has been found: offset = +0x%08lx.\n"), PatchOffsets[2]);
    _tprintf_s(TEXT("MESSAGE: [PatchSolution1] Keywords[3] has been found: offset = +0x%08lx.\n"), PatchOffsets[3]);
    _tprintf_s(TEXT("MESSAGE: [PatchSolution1] Keywords[4] has been found: offset = +0x%08lx.\n"), PatchOffsets[4]);
    return true;
}

void PatchSolution1::MakePatch(RSACipher* pCipher) const {
    std::string PublicKeyPEM;
    std::string EncryptedPEM;
    uint8_t* pFileView = _TargetFile.GetImageBaseView<uint8_t>();

    PublicKeyPEM = 
        pCipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
    Helper::ReplaceSubString(PublicKeyPEM, "\n", "\r\n");

    EncryptedPEM = Helper::NavicatCipher.EncryptString(PublicKeyPEM);

    // split encrypted_pem_pubkey to 5 part:    |160 chars|8 chars|742 chars|5 chars|5 chars|
    //                                                         |                |
    //                                                        \ /              \ /
    //                                                     ImmValue1        ImmValue3
    std::string EncryptedPEM0(EncryptedPEM.begin(), EncryptedPEM.begin() + 160);
    std::string EncryptedPEM1(EncryptedPEM.begin() + 160, EncryptedPEM.begin() + 160 + 8);
    std::string EncryptedPEM2(EncryptedPEM.begin() + 160 + 8, EncryptedPEM.begin() + 160 + 8 + 742);
    std::string EncryptedPEM3(EncryptedPEM.begin() + 160 + 8 + 742, EncryptedPEM.begin() + 160 + 8 + 742 + 5);
    std::string EncryptedPEM4(EncryptedPEM.begin() + 160 + 8 + 742 + 5, EncryptedPEM.end());
    uint32_t ImmValue1 = std::stoul(EncryptedPEM1.c_str());
    uint32_t ImmValue3 = std::stoul(EncryptedPEM3.c_str());

    // ----------------------------------
    //     process PatchOffsets[0]
    // ----------------------------------
    _tprintf_s(TEXT("@ +0x%08lx\nPrevious:\n"), PatchOffsets[0]);
    Helper::PrintMemory(pFileView + PatchOffsets[0],
                        pFileView + PatchOffsets[0] + KeywordsLength[0],
                        pFileView);
    memcpy(pFileView + PatchOffsets[0], EncryptedPEM0.c_str(), KeywordsLength[0]);
    _putts(TEXT("After:"));
    Helper::PrintMemory(pFileView + PatchOffsets[0],
                        pFileView + PatchOffsets[0] + KeywordsLength[0],
                        pFileView);
    _putts(TEXT(""));

    // ----------------------------------
    //     process PatchOffsets[1]
    // ----------------------------------
    _tprintf_s(TEXT("@ +0x%08lx\nPrevious:\n"), PatchOffsets[1]);
    Helper::PrintMemory(pFileView + PatchOffsets[1],
                        pFileView + PatchOffsets[1] + KeywordsLength[1],
                        pFileView);
    memcpy(pFileView + PatchOffsets[1], &ImmValue1, KeywordsLength[1]);
    _putts(TEXT("After:"));
    Helper::PrintMemory(pFileView + PatchOffsets[1],
                        pFileView + PatchOffsets[1] + KeywordsLength[1],
                        pFileView);
    _putts(TEXT(""));

    // ----------------------------------
    //     process PatchOffsets[2]
    // ----------------------------------
    _tprintf_s(TEXT("@ +0x%08lx\nPrevious:\n"), PatchOffsets[2]);
    Helper::PrintMemory(pFileView + PatchOffsets[2],
                        pFileView + PatchOffsets[2] + KeywordsLength[2],
                        pFileView);
    memcpy(pFileView + PatchOffsets[2], EncryptedPEM2.c_str(), KeywordsLength[2]);
    _putts(TEXT("After:"));
    Helper::PrintMemory(pFileView + PatchOffsets[2],
                        pFileView + PatchOffsets[2] + KeywordsLength[2],
                        pFileView);
    _putts(TEXT(""));

    // ----------------------------------
    //     process PatchOffsets[3]
    // ----------------------------------
    _tprintf_s(TEXT("@ +0x%08lx\nPrevious:\n"), PatchOffsets[3]);
    Helper::PrintMemory(pFileView + PatchOffsets[3],
                        pFileView + PatchOffsets[3] + KeywordsLength[3],
                        pFileView);
    memcpy(pFileView + PatchOffsets[3], &ImmValue3, KeywordsLength[3]);
    _putts(TEXT("After:"));
    Helper::PrintMemory(pFileView + PatchOffsets[3],
                        pFileView + PatchOffsets[3] + KeywordsLength[3],
                        pFileView);
    _putts(TEXT(""));

    // ----------------------------------
    //     process PatchOffsets[4]
    // ----------------------------------
    _tprintf_s(TEXT("@ +0x%08lx\nPrevious:\n"), PatchOffsets[4]);
    Helper::PrintMemory(pFileView + PatchOffsets[4],
                        pFileView + PatchOffsets[4] + KeywordsLength[4],
                        pFileView);
    memcpy(pFileView + PatchOffsets[4], EncryptedPEM4.c_str(), KeywordsLength[4]);
    _putts(TEXT("After:"));
    Helper::PrintMemory(pFileView + PatchOffsets[4],
                        pFileView + PatchOffsets[4] + KeywordsLength[4],
                        pFileView);
    _putts(TEXT(""));
}

