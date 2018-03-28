#include "def.hpp"

namespace patcher {

    BOOL BackupFile(LPCTSTR file_path) {
        size_t file_path_len = _tcslen(file_path);

        TCHAR* backup_file_path = new TCHAR[file_path_len + 16]();
        _stprintf_s(backup_file_path, file_path_len + 16, TEXT("%s%s"), file_path, TEXT(".backup"));

        if (!CopyFile(file_path, backup_file_path, TRUE)) {
            switch (GetLastError()) {
                case ERROR_FILE_NOT_FOUND:
                    _tprintf_s(TEXT("@[BackupFile]: Cannot find %s.\r\n"), file_path);
                    break;
                case ERROR_FILE_EXISTS:
                    _tprintf_s(TEXT("@[BackupFile]: Backup file already exists.\r\n"));
                    break;
                case ERROR_ACCESS_DENIED:
                    _tprintf_s(TEXT("@[BackupFile]: Access denied, please run as administrator.\r\n"));
                    break;
                default:
                    _tprintf_s(TEXT("Unknown error. CODE: 0x%08x @[BackupFile -> CopyFile]\r\n"), GetLastError());
            }
            delete[] backup_file_path;
            return FALSE;
        }

        _tprintf_s(TEXT("@[BackupFile]: %s has been backed up.\r\n"), file_path);
        delete[] backup_file_path;
        return TRUE;
    }

    RSA* GenerateRSAKey(int bits) {
        RSA* ret = RSA_generate_key(bits, RSA_F4, nullptr, nullptr);
        if (ret == nullptr) {
            _tprintf_s(TEXT("Failed to generate RSA key. CODE: 0x%08x @[GenerateRSAKey -> RSA_generate_key]\r\n"), ERR_get_error());
            return nullptr;
        }
        return ret;
    }

    BOOL WriteRSAPrivateKeyToFile(LPCTSTR filename, RSA* PrivateKey) {
#ifdef UNICODE
        int req_size = WideCharToMultiByte(CP_ACP, 0, filename, -1, nullptr, 0, nullptr, nullptr);
        if (req_size == 0) {
            _tprintf_s(TEXT("Failed to convert wchar* to char*. CODE: 0x%08x @[WriteRSAPrivateKeyToFile -> WideCharToMultiByte]\r\n"), GetLastError());
            return FALSE;
        }

        char* temp_filename = new char[req_size]();
        WideCharToMultiByte(CP_ACP, 0, filename, -1, temp_filename, req_size, nullptr, nullptr);

        BIO* b = BIO_new(BIO_s_file());
        if (b == nullptr) {
            _tprintf_s(TEXT("Failed to create BIO object. CODE: 0x%08x @[WriteRSAPrivateKeyToFile -> BIO_new]\r\n"), ERR_get_error());
            delete[] temp_filename;
            return FALSE;
        }

        if (1 != BIO_write_filename(b, temp_filename)) {
            _tprintf_s(TEXT("Failed to set target file of BIO. CODE: 0x%08x @[WriteRSAPrivateKeyToFile -> BIO_write_filename]\r\n"), ERR_get_error());

            BIO_free_all(b);
            delete[] temp_filename;
            return FALSE;
        }

        delete[] temp_filename;
#else
        BIO* b = BIO_new(BIO_s_file());
        if (b == nullptr) {
            _tprintf_s(TEXT("Failed to create BIO object. CODE: 0x%08x @[WriteRSAPrivateKeyToFile -> BIO_new]\r\n"), ERR_get_error());
            return FALSE;
        }

        if (1 != BIO_write_filename(b, filename)) {
            _tprintf_s(TEXT("Failed to set target file of BIO. CODE: 0x%08x @[WriteRSAPrivateKeyToFile -> BIO_write_filename]\r\n"), ERR_get_error());

            BIO_free_all(b);
            return FALSE;
        }
#endif
        if (1 != PEM_write_bio_RSAPrivateKey(b, PrivateKey, nullptr, nullptr, 0, nullptr, nullptr)) {
            _tprintf_s(TEXT("Failed to write RSA private key. CODE: 0x%08x @[WriteRSAPrivateKeyToFile -> PEM_write_bio_RSAPrivateKey]\r\n"), ERR_get_error());

            BIO_free_all(b);
            return FALSE;
        } else {
            BIO_free_all(b);
            return TRUE;
        }
    }

    RSA* ReadRSAPrivateKeyFromFile(LPCTSTR filename) {
#ifdef UNICODE
        int req_size = WideCharToMultiByte(CP_ACP, 0, filename, -1, nullptr, 0, nullptr, nullptr);
        if (req_size == 0) {
            _tprintf_s(TEXT("Failed to convert wchar* to char*. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> WideCharToMultiByte]\r\n"), GetLastError());
            return FALSE;
        }

        char* temp_filename = new char[req_size]();
        WideCharToMultiByte(CP_ACP, 0, filename, -1, temp_filename, req_size, nullptr, nullptr);

        BIO* b = BIO_new(BIO_s_file());
        if (b == nullptr) {
            _tprintf_s(TEXT("Failed to create BIO object. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> BIO_new]\r\n"), ERR_get_error());
            delete[] temp_filename;
            return FALSE;
        }

        if (1 != BIO_read_filename(b, temp_filename)) {
            _tprintf_s(TEXT("Failed to set target file of BIO. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> BIO_read_filename]\r\n"), ERR_get_error());

            BIO_free_all(b);
            delete[] temp_filename;
            return FALSE;
        }

        delete[] temp_filename;
#else
        BIO* b = BIO_new(BIO_s_file());
        if (b == nullptr) {
            _tprintf_s(TEXT("Failed to create BIO object. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> BIO_new]\r\n"), ERR_get_error());
            return FALSE;
        }

        if (1 != BIO_read_filename(b, filename)) {
            _tprintf_s(TEXT("Failed to set target file of BIO. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> BIO_read_filename]\r\n"), ERR_get_error());

            BIO_free_all(b);
            return FALSE;
        }
#endif
        RSA* ret = PEM_read_bio_RSAPrivateKey(b, nullptr, nullptr, nullptr);
        if (ret == nullptr) {
            _tprintf_s(TEXT("Failed to read RSA private key. CODE: 0x%08x @[ReadRSAPrivateKeyFromFile -> PEM_read_bio_RSAPrivateKey]\r\n"), ERR_get_error());

            BIO_free_all(b);
            return nullptr;
        } else {
            BIO_free_all(b);
            return ret;
        }
    }

    BOOL GetNavicatVerion(LPCTSTR exe_path, DWORD* major_ver, DWORD* minor_ver) {
        DWORD FileVersionInfoSize = GetFileVersionInfoSize(exe_path, nullptr);
        if (FileVersionInfoSize == 0) {
            _tprintf_s(TEXT("Failed to get navicat.exe verion info. CODE: 0x%08x @[GetNavicatVerion -> GetFileVersionInfoSize]\r\n"), GetLastError());
            return FALSE;
        }
        LPVOID buf = new unsigned char[FileVersionInfoSize]();
        if (FALSE == GetFileVersionInfo(exe_path, 0, FileVersionInfoSize, buf)) {
            _tprintf_s(TEXT("Failed to get navicat.exe verion info. CODE: 0x%08x @[GetNavicatVerion -> GetFileVersionInfo]\r\n"), GetLastError());
            delete[] buf;
            return FALSE;
        }

        LPVOID info_ptr;
        UINT info_len;
        if (FALSE == VerQueryValue(buf, TEXT("\\"), &info_ptr, &info_len)) {
            _tprintf_s(TEXT("Failed to get navicat.exe verion info. CODE: 0x%08x @[GetNavicatVerion -> VerQueryValue]\r\n"), GetLastError());
            delete[] buf;
            return FALSE;
        }

        *major_ver = static_cast<VS_FIXEDFILEINFO*>(info_ptr)->dwFileVersionMS;
        *minor_ver = static_cast<VS_FIXEDFILEINFO*>(info_ptr)->dwFileVersionLS;
        delete[] buf;
        return TRUE;
    }

    BOOL Check_libcc_Hash(LPCTSTR libcc_dll_path, const uint8_t expected_hash[SHA256_DIGEST_LENGTH]) {
        HANDLE hFile = CreateFile(libcc_dll_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            _tprintf_s(TEXT("Failed to open libcc.dll. CODE: 0x%08x @[Check_libcc_Hash -> CreateFile]\r\n"), GetLastError());
            return FALSE;
        }

        LARGE_INTEGER FileSize;
        if (FALSE == GetFileSizeEx(hFile, &FileSize)) {
            _tprintf_s(TEXT("Failed to get libcc.dll size. CODE: 0x%08x @[Check_libcc_Hash -> GetFileSizeEx]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        HANDLE hFileMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (hFileMap == NULL) {
            _tprintf_s(TEXT("Failed to create mapping for libcc.dll. CODE: 0x%08x @[Check_libcc_Hash -> CreateFileMapping]\r\n"), GetLastError());
            CloseHandle(hFile);
            return FALSE;
        }

        const uint8_t* libcc_data = reinterpret_cast<const uint8_t*>(MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0));
        if (libcc_data == nullptr) {
            _tprintf_s(TEXT("Failed to map libcc.dll. CODE: 0x%08x @[Check_libcc_Hash -> MapViewOfFile]\r\n"), GetLastError());
            CloseHandle(hFileMap);
            CloseHandle(hFile);
            return FALSE;
        }

        uint8_t real_hash[SHA256_DIGEST_LENGTH] = { };

        SHA256(libcc_data, FileSize.LowPart, real_hash);
        UnmapViewOfFile(libcc_data);
        CloseHandle(hFileMap);
        CloseHandle(hFile);

        if (memcmp(expected_hash, real_hash, SHA256_DIGEST_LENGTH) != 0) {
            _tprintf_s(TEXT("ERROR: SHA256 do not match.\r\n"));
            return FALSE;
        }

        return TRUE;
    }

    char* GetPEMText(RSA* PrivateKey) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (bio == nullptr) {
            _tprintf_s(TEXT("Cannot create BIO object. CODE: 0x%08x @[GetPEMText -> BIO_new]\r\n"), ERR_get_error());
            return nullptr;
        }

        if (1 != PEM_write_bio_RSA_PUBKEY(bio, PrivateKey)) {
            _tprintf_s(TEXT("Cannot write RSA-2048 public key. CODE: 0x%08x @[GetPEMText -> PEM_write_bio_RSA_PUBKEY]\r\n"), ERR_get_error());
            BIO_free_all(bio);
            return nullptr;
        }

        char* pem_data_ptr;
        int pem_data_len = BIO_get_mem_data(bio, &pem_data_ptr);

        char* ret = new char[pem_data_len + 256]();
        for (int i = 0, j = 0; i < pem_data_len; ++i, ++j) {
            if (pem_data_ptr[i] == '\n') {
                ret[j++] = '\r';
                ret[j] = pem_data_ptr[i];
            } else {
                ret[j] = pem_data_ptr[i];
            }
        }

        BIO_free_all(bio);
        return ret;
    }

}