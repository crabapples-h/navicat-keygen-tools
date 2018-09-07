#include "def.hpp"

// Solution1 is for navicat premium of which the version = 12.0.25
namespace patcher::Solution1 {

    static std::Tstring InstallationPath;

    static const CHAR Keyword0[] = 
        "D75125B70767B94145B47C1CB3C0755E"
        "7CCB8825C5DCE0C58ACF944E08280140"
        "9A02472FAFFD1CD77864BB821AE36766"
        "FEEDE6A24F12662954168BFA314BD950"
        "32B9D82445355ED7BC0B880887D650F5";

    static const DWORD KeywordSize0 = sizeof(Keyword0) - 1;

    static const uint8_t Keyword1[] = {
        0xFE, 0xEA, 0xBC, 0x01
    };

    static const DWORD KeywordSize1 = sizeof(Keyword1);

    static const CHAR Keyword2[] =
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

    static const DWORD KeywordSize2 = sizeof(Keyword2) - 1;

    static const uint8_t Keyword3[] = {
        0x59, 0x08, 0x01, 0x00
    };

    static const DWORD KeywordSize3 = sizeof(Keyword3);

    static const CHAR Keyword4[] = "92933";

    static const DWORD KeywordSize4 = sizeof(Keyword4) - 1;

    static DWORD KeywordOffset[5] = { -1, -1, -1, -1, -1 };

    static LPCTSTR TargetName = TEXT("libcc.dll");

    static HANDLE hTarget = INVALID_HANDLE_VALUE;
    static HANDLE hTargetMap = NULL;
    static PVOID lpFileContent = NULL;

    BOOL Init(const std::Tstring& Path) {
        BOOL bSuccess = FALSE;
        DWORD dwLastError = ERROR_SUCCESS;
        DWORD attr = INVALID_FILE_ATTRIBUTES;

        attr = GetFileAttributes(Path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ GetFileAttributes. CODE: 0x%08X\n"), dwLastError);
            goto ON_Init_ERROR;
        }

        if ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Error: Path is not a directory.\n"));
            goto ON_Init_ERROR;
        }

        InstallationPath = Path;
        if (InstallationPath.back() != TEXT('\\') && InstallationPath.back() != TEXT('/'))
            InstallationPath.push_back(TEXT('/'));  // for Linux compatible

        bSuccess = TRUE;

    ON_Init_ERROR:
        return bSuccess;
    }

    BOOL CheckKey(RSACipher* cipher) {
        BOOL bOk = FALSE;
        std::string RSAPublicKeyPEM;

        RSAPublicKeyPEM = cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
        if (RSAPublicKeyPEM.empty()) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: cipher->ExportKeyString failed.\n"));
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

        std::string encrypted_pem_text = EncryptPublicKey(RSAPublicKeyPEM.c_str(),
                                                          RSAPublicKeyPEM.length());

        if (encrypted_pem_text[160] > '9' || encrypted_pem_text[160] < '1') 
            return FALSE;

        for (int i = 1; i < 8; ++i)
            if (encrypted_pem_text[160 + i] > '9' || encrypted_pem_text[160 + i] < '0') 
                return FALSE;

        if (encrypted_pem_text[910] > '9' || encrypted_pem_text[910] < '1') 
            return FALSE;

        for (int i = 1; i < 5; ++i)
            if (encrypted_pem_text[910 + i] > '9' || encrypted_pem_text[910 + i] < '0')
                return FALSE;

        return TRUE;
    }

    static PIMAGE_SECTION_HEADER ImageSectionHeader(PVOID lpBase, LPCSTR lpSectionName) {
        IMAGE_DOS_HEADER* pFileHeader = NULL;
        IMAGE_NT_HEADERS* pNtHeader = NULL;
        IMAGE_SECTION_HEADER* pSectionHeaders = NULL;

        pFileHeader = (IMAGE_DOS_HEADER*)lpBase;
        if (pFileHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return NULL;

        pNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)lpBase + pFileHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        pSectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)pNtHeader +
                                                  offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
                                                  pNtHeader->FileHeader.SizeOfOptionalHeader);
        for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
            if (_stricmp((const char*)pSectionHeaders[i].Name, lpSectionName) == 0)
                return pSectionHeaders + i;

        return NULL;
    }

    BOOL FindTargetFile() {
        DWORD dwLastError = ERROR_SUCCESS;
        std::Tstring&& TargetFileName = InstallationPath + TargetName;
        
        hTarget = CreateFile(TargetFileName.c_str(),
                             GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ,
                             NULL,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL,
                             NULL);
        if (hTarget == INVALID_HANDLE_VALUE) {
            dwLastError = GetLastError();
            if (dwLastError == ERROR_FILE_NOT_FOUND) {
                return FALSE;
            } else {
                _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
                _tprintf_s(TEXT("Unexpected Error @ CreateFile. CODE: 0x%08X\n"), dwLastError);
                return FALSE;
            }
        }
        
        return TRUE;
    }

    BOOL FindOffset() {
        BOOL bSuccess = FALSE;
        DWORD dwLastError = ERROR_SUCCESS;
        IMAGE_SECTION_HEADER* textSection = NULL;
        IMAGE_SECTION_HEADER* rdataSection = NULL;

        hTargetMap = CreateFileMapping(hTarget,
                                       NULL,
                                       PAGE_READWRITE,
                                       0,
                                       0,
                                       NULL);
        if (hTargetMap == NULL) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ CreateFileMapping. CODE: 0x%08X\n"), dwLastError);
            goto ON_FindOffset_ERROR;
        }

        lpFileContent = MapViewOfFile(hTargetMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if (lpFileContent == NULL) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ MapViewOfFile. CODE: 0x%08X\n"), dwLastError);
            goto ON_FindOffset_ERROR;
        }

        textSection = ImageSectionHeader(lpFileContent, ".text");
        if (textSection == NULL) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: Cannot find .text section.\n"));
            goto ON_FindOffset_ERROR;
        }

        rdataSection = ImageSectionHeader(lpFileContent, ".rdata");
        if (textSection == NULL) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: Cannot find .rdata section.\n"));
            goto ON_FindOffset_ERROR;
        }

        // -------------------------
        // try to search keyword0
        // -------------------------
        for (DWORD i = 0; i < rdataSection->SizeOfRawData; ++i) {
            if (memcmp((uint8_t*)lpFileContent + rdataSection->PointerToRawData + i, Keyword0, KeywordSize0) == 0) {
                KeywordOffset[0] = rdataSection->PointerToRawData + i;
                break;
            }
        }

        if (KeywordOffset[0] == -1) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: Cannot find Keyword0.\n"));
            goto ON_FindOffset_ERROR;
        } else {
            _tprintf_s(TEXT("Keyword0 has been found: offset = +0x%08X.\n"), KeywordOffset[0]);
        }

        // -------------------------
        // try to search keyword1
        // -------------------------
        for (DWORD i = 0; i < textSection->SizeOfRawData; ++i) {
            if (memcmp((uint8_t*)lpFileContent + textSection->PointerToRawData + i, Keyword1, KeywordSize1) == 0) {
                KeywordOffset[1] = textSection->PointerToRawData + i;
                break;
            }
        }

        if (KeywordOffset[1] == -1) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: Cannot find Keyword1.\n"));
            goto ON_FindOffset_ERROR;
        } else {
            _tprintf_s(TEXT("Keyword1 has been found: offset = +0x%08X.\n"), KeywordOffset[1]);
        }

        // -------------------------
        // try to search keyword2
        // -------------------------
        for (DWORD i = 0; i < rdataSection->SizeOfRawData; ++i) {
            if (memcmp((uint8_t*)lpFileContent + rdataSection->PointerToRawData + i, Keyword2, KeywordSize2) == 0) {
                KeywordOffset[2] = rdataSection->PointerToRawData + i;
                break;
            }
        }

        if (KeywordOffset[2] == -1) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: Cannot find Keyword2.\n"));
            goto ON_FindOffset_ERROR;
        } else {
            _tprintf_s(TEXT("Keyword2 has been found: offset = +0x%08X.\n"), KeywordOffset[2]);
        }

        // -------------------------
        // try to search keyword3
        // -------------------------
        for (DWORD i = 0; i < textSection->SizeOfRawData; ++i) {
            if (memcmp((uint8_t*)lpFileContent + textSection->PointerToRawData + i, Keyword3, KeywordSize3) == 0) {
                KeywordOffset[3] = textSection->PointerToRawData + i;
                break;
            }
        }

        if (KeywordOffset[3] == -1) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: Cannot find Keyword3.\n"));
            goto ON_FindOffset_ERROR;
        } else {
            _tprintf_s(TEXT("Keyword3 has been found: offset = +0x%08X.\n"), KeywordOffset[3]);
        }

        // -------------------------
        // try to search keyword4
        // -------------------------
        for (DWORD i = 0; i < rdataSection->SizeOfRawData; ++i) {
            if (memcmp((uint8_t*)lpFileContent + rdataSection->PointerToRawData + i, Keyword4, KeywordSize4) == 0) {
                KeywordOffset[4] = rdataSection->PointerToRawData + i;
                break;
            }
        }

        if (KeywordOffset[4] == -1) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: Cannot find Keyword4.\n"));
            goto ON_FindOffset_ERROR;
        } else {
            _tprintf_s(TEXT("Keyword4 has been found: offset = +0x%08X.\n"), KeywordOffset[4]);
        }
        
        bSuccess = TRUE;

    ON_FindOffset_ERROR:
        return bSuccess;
    }

    BOOL BackupFile() {
        BOOL bSuccess = FALSE;
        DWORD dwLastError = ERROR_SUCCESS;
        std::Tstring&& TargetFileName = InstallationPath + TargetName;
        std::Tstring&& BackupFileName = InstallationPath + TargetName + TEXT(".backup");

        if (!CopyFile(TargetFileName.c_str(), BackupFileName.c_str(), TRUE)) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ CopyFile. CODE: 0x%08X\n"), dwLastError);
            goto ON_BackupFile_ERROR;
        }

        bSuccess = TRUE;
    ON_BackupFile_ERROR:
        return bSuccess;
    }

    BOOL Do(RSACipher* cipher) {
        std::string RSAPublicKeyPEM;
        std::string encrypted_pem_pubkey;

        RSAPublicKeyPEM = cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
        if (RSAPublicKeyPEM.empty()) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: cipher->ExportKeyString failed.\n"));
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

        encrypted_pem_pubkey = EncryptPublicKey(RSAPublicKeyPEM.c_str(), RSAPublicKeyPEM.length());

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

        _tprintf_s(TEXT("\n"));
        _tprintf_s(TEXT("@Offset +0x%08X, write string:\n"), KeywordOffset[0]);
        printf_s("\"%s\"\n\n", encrypted_pem_pubkey0.c_str());
        memcpy((uint8_t*)lpFileContent + KeywordOffset[0], encrypted_pem_pubkey0.c_str(), 160);

        _tprintf_s(TEXT("@Offset +0x%08X, write uint32_t:\n"), KeywordOffset[1]);
        printf_s("0x%08X\n\n", imm1);
        memcpy((uint8_t*)lpFileContent + KeywordOffset[1], &imm1, sizeof(uint32_t));

        _tprintf_s(TEXT("@Offset +0x%08X, write string:\n"), KeywordOffset[2]);
        printf_s("\"%s\"\n\n", encrypted_pem_pubkey2.c_str());
        memcpy((uint8_t*)lpFileContent + KeywordOffset[2], encrypted_pem_pubkey2.c_str(), 742);

        _tprintf_s(TEXT("@Offset +0x%08X, write uint32_t:\n"), KeywordOffset[3]);
        printf_s("0x%08X\n\n", imm3);
        memcpy((uint8_t*)lpFileContent + KeywordOffset[3], &imm3, sizeof(uint32_t));

        _tprintf_s(TEXT("@Offset +0x%08X, write string:\n"), KeywordOffset[4]);
        printf_s("\"%s\"\n\n", encrypted_pem_pubkey4.c_str());
        memcpy((uint8_t*)lpFileContent + KeywordOffset[4], encrypted_pem_pubkey4.c_str(), 5);

        return TRUE;
    }

    VOID Finalize() {
        if (lpFileContent) {
            UnmapViewOfFile(lpFileContent);
            lpFileContent = NULL;
        }
        if (hTargetMap) {
            CloseHandle(hTargetMap);
            hTargetMap = NULL;
        }
        if (hTarget) {
            CloseHandle(hTarget);
            hTarget = INVALID_HANDLE_VALUE;
        }
    }

}