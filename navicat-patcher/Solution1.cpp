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

    static BOOL FindPatchOffset(LPCTSTR libcc_dll_path, DWORD Offset[5]) {
        Offset[0] = 0;
        Offset[1] = 0;
        Offset[2] = 0;
        Offset[3] = 0;
        Offset[4] = 0;

        HANDLE h_libcc = CreateFile(libcc_dll_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h_libcc == INVALID_HANDLE_VALUE) {
            _tprintf_s(TEXT("Failed to open libcc.dll. CODE: 0x%08x @[FindPatchOffset -> CreateFile]\r\n"), GetLastError());
            return FALSE;
        }

        // DWORD is enough, you know libcc.dll cannot be larger than 4GB
        DWORD libcc_size = GetFileSize(h_libcc, nullptr);
        HANDLE h_libcc_map = CreateFileMapping(h_libcc, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (h_libcc_map == NULL) {
            _tprintf_s(TEXT("Failed to create mapping for libcc.dll. CODE: 0x%08x @[FindPatchOffset -> CreateFileMapping]\r\n"), GetLastError());
            CloseHandle(h_libcc);
            return FALSE;
        }

        const uint8_t* libcc = reinterpret_cast<const uint8_t*>(MapViewOfFile(h_libcc_map, FILE_MAP_READ, 0, 0, 0));
        if (libcc == nullptr) {
            _tprintf_s(TEXT("Failed to map libcc.dll. CODE: 0x%08x @[FindPatchOffset -> MapViewOfFile]\r\n"), GetLastError());
            CloseHandle(h_libcc_map);
            CloseHandle(h_libcc);
            return FALSE;
        }

        const IMAGE_DOS_HEADER* libcc_dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(libcc);

        // check dos signature
        if (libcc_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            _tprintf_s(TEXT("libcc.dll does not have a valid DOS header. @[FindPatchOffset]\r\n"));
            UnmapViewOfFile(libcc);
            CloseHandle(h_libcc_map);
            CloseHandle(h_libcc);
            return FALSE;
        }

        const IMAGE_NT_HEADERS* libcc_nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(libcc + libcc_dos_header->e_lfanew);

        // check nt signature
        if (libcc_nt_header->Signature != IMAGE_NT_SIGNATURE) {
            _tprintf_s(TEXT("libcc.dll does not have a valid NT header. @[FindPatchOffset]\r\n"));
            UnmapViewOfFile(libcc);
            CloseHandle(h_libcc_map);
            CloseHandle(h_libcc);
            return FALSE;
        }

        // check if a dll
        if ((libcc_nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
            _tprintf_s(TEXT("libcc.dll is not a DLL file. @[FindPatchOffset]\r\n"));
            UnmapViewOfFile(libcc);
            CloseHandle(h_libcc_map);
            CloseHandle(h_libcc);
            return FALSE;
        }

        // check if 32-bits or 64-bits
#if defined(_M_X64)
        if (libcc_nt_header->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || libcc_nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            _tprintf_s(TEXT("libcc.dll is not a 64-bits DLL file. @[FindPatchOffset]\r\n"));
#elif defined(_M_IX86)
        if (libcc_nt_header->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || libcc_nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
#else
#error "unknown arch"
#endif
            _tprintf_s(TEXT("libcc.dll is not a 32-bits DLL file. @[FindPatchOffset]\r\n"));
            UnmapViewOfFile(libcc);
            CloseHandle(h_libcc_map);
            CloseHandle(h_libcc);
            return FALSE;
        }

        WORD section_num = libcc_nt_header->FileHeader.NumberOfSections;
        const IMAGE_SECTION_HEADER* libcc_section_headers = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            libcc + libcc_dos_header->e_lfanew + sizeof(libcc_nt_header->Signature) + sizeof(libcc_nt_header->FileHeader) + libcc_nt_header->FileHeader.SizeOfOptionalHeader
        );

        const IMAGE_SECTION_HEADER* rdata_section = nullptr;
        for (WORD i = 0; i < section_num; ++i) {
            if (*reinterpret_cast<const uint64_t*>(libcc_section_headers[i].Name) == 0x61746164722e) {   // b'\x00\x00atadr.'
                rdata_section = libcc_section_headers + i;
                break;
            }
        }
        if (rdata_section == nullptr) {
            _tprintf_s(TEXT(".rdata section is not found. @[FindPatchOffset]\r\n"));
            UnmapViewOfFile(libcc);
            CloseHandle(h_libcc_map);
            CloseHandle(h_libcc);
            return FALSE;
        }

        const IMAGE_SECTION_HEADER* text_section = nullptr;
        for (WORD i = 0; i < section_num; ++i) {
            if (*reinterpret_cast<const uint64_t*>(libcc_section_headers[i].Name) == 0x747865742e) {   // b'\x00\x00\x00txet.'
                text_section = libcc_section_headers + i;
                break;
            }
        }
        if (text_section == nullptr) {
            _tprintf_s(TEXT(".text section is not found. @[FindPatchOffset]\r\n"));
            UnmapViewOfFile(libcc);
            CloseHandle(h_libcc_map);
            CloseHandle(h_libcc);
            return FALSE;
        }

        // search offset[0] 
        {
            const uint8_t keyword[] = "D75125B70767B94145B47C1CB3C0755E";
            const uint8_t* start = libcc + rdata_section->PointerToRawData;
            DWORD section_size = rdata_section->SizeOfRawData;
            for (DWORD i = 0; i < section_size; ++i) {
                if (start[i] == keyword[0]) {
                    bool found = true;
                    for (DWORD j = 1; j < sizeof(keyword) - 1; ++j)
                        if (start[i + j] != keyword[j]) {
                            found = false;
                            break;
                        }
                    if (found) {
                        Offset[0] = rdata_section->PointerToRawData + i;
                        break;
                    }
                }
            }
        }

        // search offset[2] 
        {
            const uint8_t keyword[] = "E1CED09B9C2186BF71A70C0FE2F1E0AE";
            const uint8_t* start = libcc + rdata_section->PointerToRawData;
            DWORD section_size = rdata_section->SizeOfRawData;
            for (DWORD i = 0; i < section_size; ++i) {
                if (start[i] == keyword[0]) {
                    bool found = true;
                    for (DWORD j = 1; j < sizeof(keyword) - 1; ++j)
                        if (start[i + j] != keyword[j]) {
                            found = false;
                            break;
                        }
                    if (found) {
                        Offset[2] = rdata_section->PointerToRawData + i;
                        break;
                    }
                }
            }
        }

        // search offset[4] 
        {
            const uint8_t keyword[] = "92933";
            const uint8_t* start = libcc + rdata_section->PointerToRawData;
            DWORD section_size = rdata_section->SizeOfRawData;
            for (DWORD i = 0; i < section_size; ++i) {
                if (start[i] == keyword[0]) {
                    bool found = true;
                    for (DWORD j = 1; j < sizeof(keyword) - 1; ++j)
                        if (start[i + j] != keyword[j]) {
                            found = false;
                            break;
                        }
                    if (found) {
                        Offset[4] = rdata_section->PointerToRawData + i;
                        break;
                    }
                }
            }
        }

        // search offset[1]
        {
            const uint8_t keyword[] = { 0xfe, 0xea, 0xbc, 0x01 };
            const uint8_t* start = libcc + text_section->PointerToRawData;
            DWORD section_size = text_section->SizeOfRawData;
            for (DWORD i = 0; i < section_size; ++i) {
                if (start[i] == keyword[0]) {
                    bool found = true;
                    for (DWORD j = 1; j < sizeof(keyword); ++j)
                        if (start[i + j] != keyword[j]) {
                            found = false;
                            break;
                        }
                    if (found) {
                        Offset[1] = text_section->PointerToRawData + i;
                        break;
                    }
                }
            }
        }

        // search offset[3]
        {
            const uint8_t keyword[] = { 0x59, 0x08, 0x01, 0x00 };
            const uint8_t* start = libcc + text_section->PointerToRawData;
            DWORD section_size = text_section->SizeOfRawData;
            for (DWORD i = 0; i < section_size; ++i) {
                if (start[i] == keyword[0]) {
                    bool found = true;
                    for (DWORD j = 1; j < sizeof(keyword); ++j)
                        if (start[i + j] != keyword[j]) {
                            found = false;
                            break;
                        }
                    if (found) {
                        Offset[3] = text_section->PointerToRawData + i;
                        break;
                    }
                }
            }
        }

        UnmapViewOfFile(libcc);
        CloseHandle(h_libcc_map);
        CloseHandle(h_libcc);

        if (Offset[0] == 0 || Offset[1] == 0 || Offset[2] == 0 || Offset[3] == 0 || Offset[4] == 0) {
            _tprintf_s(TEXT("Failed to find all patch offset. Is libcc.dll from official? Or you've patched?\r\n"));
            return FALSE;
        } else {
            return TRUE;
        }
    }

    BOOL Do(LPCTSTR libcc_dll_path, LPCTSTR prepared_key_file) {
//         uint8_t expected_hash[SHA256_DIGEST_LENGTH] = {
//             0x60, 0x7e, 0x0a, 0x84, 0xc7, 0x59, 0x66, 0xb0,
//             0x0f, 0x3d, 0x12, 0xfa, 0x83, 0x3e, 0x91, 0xd1,
//             0x59, 0xe4, 0xf5, 0x1a, 0xc5, 0x1b, 0x6b, 0xa6,
//             0x6f, 0x98, 0xd0, 0xc3, 0xcb, 0xef, 0xdc, 0xe0
//         };
// 
//         if (!Check_libcc_Hash(libcc_dll_path, expected_hash))
//             return FALSE;

        DWORD Patch_Offset[5];
        if (!FindPatchOffset(libcc_dll_path, Patch_Offset)) 
            return FALSE;
        
            

        if (!BackupFile(libcc_dll_path))
            return FALSE;

        RSA* PrivateKey = nullptr;
        if (prepared_key_file != nullptr) {
            PrivateKey = ReadRSAPrivateKeyFromFile(prepared_key_file);
            if (PrivateKey == nullptr)
                return FALSE;

            if (!CheckRSAKeyIsAppropriate(PrivateKey)) {
                _tprintf_s(TEXT("The key is not appropriate to use. @[patcher::Solution1::Do -> CheckRSAKeyIsAppropriate]\r\n"));
                RSA_free(PrivateKey);
                return FALSE;
            }

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

        HANDLE hFile = CreateFile(libcc_dll_path, GENERIC_WRITE, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            _tprintf_s(TEXT("Failed to open libcc.dll. CODE: 0x%08x @[patcher::Solution1::Do -> CreateFile]\r\n"), GetLastError());
            return FALSE;
        }
        
        // Start from win8, lpNumberOfBytesWritten parameter in WriteFile can be null if lpOverlapped is null.
        // But win7 is not. lpNumberOfBytesWritten cannot be null if lpOverlapped is null. 
        // However MSDN does not mention that.
        DWORD WrittenBytes;

        // start patch 0
        _tprintf_s(TEXT("\r\nStart to do patch 0......\r\n"));
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, Patch_Offset[0], nullptr, FILE_BEGIN)) {
            _tprintf_s(TEXT("Failed to set file pointer. CODE: 0x%08x @[patcher::Solution1::Do -> SetFilePointer]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }
        
        _tprintf_s(TEXT("At offset +0x%08x, write:\r\n\"%hs\"\r\n"), Patch_Offset[0], encrypted_pem_pubkey0.c_str());
        if (FALSE == WriteFile(hFile, encrypted_pem_pubkey0.c_str(), encrypted_pem_pubkey0.length(), &WrittenBytes, nullptr)) {
            _tprintf_s(TEXT("Failed to write patch 0. CODE: 0x%08x @[patcher::Solution1::Do -> WriteFile]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        _tprintf_s(TEXT("patch 0 done.....\r\n"));

        // start patch 1
        _tprintf_s(TEXT("\r\nStart to do patch 1.....\r\n"));
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, Patch_Offset[1], nullptr, FILE_BEGIN)) {
            _tprintf_s(TEXT("Failed to set file pointer. CODE: 0x%08x @[patcher::Solution1::Do -> SetFilePointer]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        _tprintf_s(TEXT("At offset +0x%08x, write immediate value %d (type: uint32_t)\r\n"), Patch_Offset[1], imm1);
        if (FALSE == WriteFile(hFile, &imm1, sizeof(imm1), &WrittenBytes, nullptr)) {
            _tprintf_s(TEXT("Failed to write patch 1. CODE: 0x%08x @[patcher::Solution1::Do -> WriteFile]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        _tprintf_s(TEXT("patch 1 done.....\r\n"));

        // start patch 2
        _tprintf_s(TEXT("\r\nStart to do patch 2.....\r\n"));
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, Patch_Offset[2], nullptr, FILE_BEGIN)) {
            _tprintf_s(TEXT("Failed to set file pointer. CODE: 0x%08x @[patcher::Solution1::Do -> SetFilePointer]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        _tprintf_s(TEXT("At offset +0x%08x, write:\r\n\"%hs\"\r\n"), Patch_Offset[2], encrypted_pem_pubkey2.c_str());
        if (FALSE == WriteFile(hFile, encrypted_pem_pubkey2.c_str(), encrypted_pem_pubkey2.length(), &WrittenBytes, nullptr)) {
            _tprintf_s(TEXT("Failed to write patch 2. CODE: 0x%08x @[patcher::Solution1::Do -> WriteFile]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        _tprintf_s(TEXT("patch 2 done.....\r\n"));

        // start patch 3
        _tprintf_s(TEXT("\r\nStart to do patch 3.....\r\n"));
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, Patch_Offset[3], nullptr, FILE_BEGIN)) {
            _tprintf_s(TEXT("Failed to set file pointer. CODE: 0x%08x @[patcher::Solution1::Do -> SetFilePointer]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        _tprintf_s(TEXT("At offset +0x%08x, write immediate value %d (type: uint32_t)\r\n"), Patch_Offset[3], imm3);
        if (FALSE == WriteFile(hFile, &imm3, sizeof(imm3), &WrittenBytes, nullptr)) {
            _tprintf_s(TEXT("Failed to write patch 3. CODE: 0x%08x @[patcher::Solution1::Do -> WriteFile]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        _tprintf_s(TEXT("patch 3 done.....\r\n"));

        // start patch 4
        _tprintf_s(TEXT("\r\nStart to do patch 4.....\r\n"));
        if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, Patch_Offset[4], nullptr, FILE_BEGIN)) {
            _tprintf_s(TEXT("Failed to set file pointer. CODE: 0x%08x @[patcher::Solution1::Do -> SetFilePointer]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        _tprintf_s(TEXT("At offset +0x%08x, write:\r\n\"%hs\"\r\n"), Patch_Offset[4], encrypted_pem_pubkey4.c_str());
        if (FALSE == WriteFile(hFile, encrypted_pem_pubkey4.c_str(), encrypted_pem_pubkey4.length(), &WrittenBytes, nullptr)) {
            _tprintf_s(TEXT("Failed to write patch 4. CODE: 0x%08x @[patcher::Solution1::Do -> WriteFile]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        _tprintf_s(TEXT("patch 4 done.....\r\n\r\n"));

        return TRUE;
    }

}