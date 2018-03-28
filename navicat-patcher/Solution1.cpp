#include "def.hpp"

// Solution1 is for navicat premium of which the version = 12.0.25
namespace patcher::Solution1 {

    static BOOL CheckRSAKeyIsAppropriate(RSA* PrivateKey) {
        char* pem_pubkey = GetPEMText(PrivateKey);
        if (pem_pubkey == nullptr)
            return FALSE;

        std::string encrypted_pem_text = EncryptPublicKey(pem_pubkey, strlen(pem_pubkey));
        delete[] pem_pubkey;

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

    static RSA* GenerateAppropriateRSAKey() {
        while (true) {
            RSA* Key = GenerateRSAKey();
            if (Key == nullptr)
                return nullptr;

            if (CheckRSAKeyIsAppropriate(Key)) {
                return Key;
            } else {
                RSA_free(Key);
            }
        }
    }

    BOOL Do(LPCTSTR libcc_dll_path, LPCTSTR prepared_key_file) {
        uint8_t expected_hash[SHA256_DIGEST_LENGTH] = {
            0x60, 0x7e, 0x0a, 0x84, 0xc7, 0x59, 0x66, 0xb0,
            0x0f, 0x3d, 0x12, 0xfa, 0x83, 0x3e, 0x91, 0xd1,
            0x59, 0xe4, 0xf5, 0x1a, 0xc5, 0x1b, 0x6b, 0xa6,
            0x6f, 0x98, 0xd0, 0xc3, 0xcb, 0xef, 0xdc, 0xe0
        };

        if (!Check_libcc_Hash(libcc_dll_path, expected_hash))
            return FALSE;

        if (!BackupFile(libcc_dll_path))
            return FALSE;

        RSA* PrivateKey;
        if (prepared_key_file != nullptr) {
            PrivateKey = ReadRSAPrivateKeyFromFile(prepared_key_file);
            if (PrivateKey == nullptr)
                return FALSE;
        } else {
            PrivateKey = GenerateAppropriateRSAKey();
            if (PrivateKey == nullptr)
                return FALSE;

            if (!WriteRSAPrivateKeyToFile(TEXT("RegPrivateKey.pem"), PrivateKey)) {
                RSA_free(PrivateKey);
                return FALSE;
            }
        }

        char* pem_pubkey = GetPEMText(PrivateKey);
        if (pem_pubkey == nullptr)
            return FALSE;

        std::string encrypted_pem_pubkey = EncryptPublicKey(pem_pubkey, strlen(pem_pubkey));

        delete[] pem_pubkey;    // we do not need it anymore
        RSA_free(PrivateKey);   // we do not need it anymore

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

        uint32_t patch_offset0 = 0x1A12090;
        uint32_t patch_offset1 = 0x59D799;
        uint32_t patch_offset2 = 0x1A11DA0;
        uint32_t patch_offset3 = 0x59D77F;
        uint32_t patch_offset4 = 0x1A11D8C;

        HANDLE hFile = CreateFile(libcc_dll_path, GENERIC_WRITE, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            _tprintf_s(TEXT("Failed to open libcc.dll. CODE: 0x%08x @[patcher::Solution1::Do -> CreateFile]\r\n"), GetLastError());
            return FALSE;
        }

        // start patch 0
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, patch_offset0, nullptr, FILE_BEGIN)) {
            _tprintf_s(TEXT("Failed to set file pointer. CODE: 0x%08x @[patcher::Solution1::Do -> SetFilePointer]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        if (FALSE == WriteFile(hFile, encrypted_pem_pubkey0.c_str(), encrypted_pem_pubkey0.length(), nullptr, nullptr)) {
            _tprintf_s(TEXT("Failed to write patch 0. CODE: 0x%08x @[patcher::Solution1::Do -> WriteFile]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        // start patch 1
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, patch_offset1, nullptr, FILE_BEGIN)) {
            _tprintf_s(TEXT("Failed to set file pointer. CODE: 0x%08x @[patcher::Solution1::Do -> SetFilePointer]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        if (FALSE == WriteFile(hFile, &imm1, sizeof(imm1), nullptr, nullptr)) {
            _tprintf_s(TEXT("Failed to write patch 1. CODE: 0x%08x @[patcher::Solution1::Do -> WriteFile]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        // start patch 2
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, patch_offset2, nullptr, FILE_BEGIN)) {
            _tprintf_s(TEXT("Failed to set file pointer. CODE: 0x%08x @[patcher::Solution1::Do -> SetFilePointer]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        if (FALSE == WriteFile(hFile, encrypted_pem_pubkey2.c_str(), encrypted_pem_pubkey2.length(), nullptr, nullptr)) {
            _tprintf_s(TEXT("Failed to write patch 2. CODE: 0x%08x @[patcher::Solution1::Do -> WriteFile]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        // start patch 3
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, patch_offset3, nullptr, FILE_BEGIN)) {
            _tprintf_s(TEXT("Failed to set file pointer. CODE: 0x%08x @[patcher::Solution1::Do -> SetFilePointer]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        if (FALSE == WriteFile(hFile, &imm3, sizeof(imm3), nullptr, nullptr)) {
            _tprintf_s(TEXT("Failed to write patch 3. CODE: 0x%08x @[patcher::Solution1::Do -> WriteFile]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        // start patch 4
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, patch_offset4, nullptr, FILE_BEGIN)) {
            _tprintf_s(TEXT("Failed to set file pointer. CODE: 0x%08x @[patcher::Solution1::Do -> SetFilePointer]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        if (FALSE == WriteFile(hFile, encrypted_pem_pubkey4.c_str(), encrypted_pem_pubkey4.length(), nullptr, nullptr)) {
            _tprintf_s(TEXT("Failed to write patch 4. CODE: 0x%08x @[patcher::Solution1::Do -> WriteFile]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        return TRUE;
    }

}