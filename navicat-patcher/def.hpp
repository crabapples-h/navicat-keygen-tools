#pragma once
#include <tchar.h>
#include <windows.h>
#include <string>

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// OpenSSL precompiled lib, download from https://www.npcglib.org/~stathis/blog/precompiled-openssl/, MSVC2015 version
// direct link https://www.npcglib.org/~stathis/downloads/openssl-1.1.0f-vs2015.7z
// x86: "D:\openssl-1.1.0f-vs2015\include" has been add to include path.    (modify it at project properties if necessary)
//      "D:\openssl-1.1.0f-vs2015\lib" has been add to library path.        (modify it at project properties if necessary)
// x64: "D:\openssl-1.1.0f-vs2015\include64" has been add to include path.  (modify it at project properties if necessary)
//      "D:\openssl-1.1.0f-vs2015\lib64" has been add to library path.      (modify it at project properties if necessary)
#ifdef _DEBUG
#pragma comment(lib, "libcryptoMTd.lib")
#else
#pragma comment(lib, "libcryptoMT.lib")
#endif
#pragma comment(lib, "WS2_32.lib")      // some symbol are used in OpenSSL lib
#pragma comment(lib, "Crypt32.lib")     // some symbol are used in OpenSSL lib
#pragma comment(lib, "version.lib")     // GetFileVersionInfoSize, GetFileVersionInfo, VerQueryValue are in this lib

namespace patcher {

    BOOL BackupFile(LPCTSTR file_path);

    RSA* GenerateRSAKey(int bits = 2048);

    BOOL WriteRSAPrivateKeyToFile(LPCTSTR filename, RSA* PrivateKey);
    RSA* ReadRSAPrivateKeyFromFile(LPCTSTR filename);

    BOOL GetNavicatVerion(LPCTSTR exe_path, DWORD* major_ver, DWORD* minor_ver);

    std::string EncryptPublicKey(const char* public_key, size_t len);

    BOOL Check_libcc_Hash(LPCTSTR libcc_dll_path, const uint8_t expected_hash[SHA256_DIGEST_LENGTH]);

    char* GetPEMText(RSA* PrivateKey);

    namespace Solution0 {
        BOOL Do(LPCTSTR navicat_exe_path, LPCTSTR prepared_key_file = nullptr);
    }

    namespace Solution1 {
        BOOL Do(LPCTSTR libcc_dll_path, LPCTSTR prepared_key_file = nullptr);
    }

}