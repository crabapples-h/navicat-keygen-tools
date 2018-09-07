#pragma once
#include <tchar.h>
#include <windows.h>
#include <string>

#include "RSACipher.hpp"
#pragma comment(lib, "version.lib")     // GetFileVersionInfoSize, GetFileVersionInfo, VerQueryValue are in this lib

namespace std {
#ifdef UNICODE
    typedef wstring Tstring;
#else
    typedef string Tstring;
#endif // UNICODE
}

namespace patcher {

    std::string EncryptPublicKey(const char* public_key, size_t len);

    namespace Solution0 {
        BOOL Init(const std::Tstring& Path);
        BOOL CheckKey(RSACipher* cipher);
        BOOL FindTargetFile();
        BOOL CheckFile();
        BOOL BackupFile();
        BOOL Do(RSACipher* cipher);
        BOOL GetVersion(LPDWORD lpMajorVer, LPDWORD lpMinorVer);
        VOID Finalize();
    }

    namespace Solution1 {
        BOOL Init(const std::Tstring& Path);
        BOOL CheckKey(RSACipher* cipher);
        BOOL FindTargetFile();
        BOOL FindOffset();
        BOOL BackupFile();
        BOOL Do(RSACipher* cipher);
        VOID Finalize();
    }

}