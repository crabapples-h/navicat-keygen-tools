#pragma once
#include <tchar.h>
#include <windows.h>
#include <string>
#include "RSACipher.hpp"

#ifdef UNICODE
namespace std { typedef wstring Tstring; }
#else
namespace std { typedef string Tstring; }
#endif

namespace Helper {
    std::string EncryptPublicKey(const std::string& PublicKeyString);

    bool ConvertToUTF8(LPCSTR from, std::string& to);
    bool ConvertToUTF8(LPCWSTR from, std::string& to);
    bool ConvertToUTF8(std::string& str);

    void ErrorReport(LPCTSTR at, UINT line, LPCTSTR msg);
    void ErrorReport(LPCTSTR at, UINT line, LPCTSTR msg, DWORD err_code);

    void PrintMemory(const void* a, const void* b, const void* base);
}

#define REPORT_ERROR(msg) Helper::ErrorReport(TEXT(__FUNCTION__), __LINE__, TEXT(msg))
#define REPORT_ERROR_WITH_CODE(msg, err_code) Helper::ErrorReport(TEXT(__FUNCTION__), __LINE__, TEXT(msg), (err_code))

#define PRINT_MESSAGE(msg) _tprintf_s(TEXT("%s\n"), TEXT(msg))
#define PRINT_LPCTSTR(msg) _tprintf_s(TEXT("%s\n"), (msg))
#define PRINT_LPCSTR(msg) printf_s("%s\n", (msg))
#define PRINT_LPCWSTR(msg) wprintf_s(L"%s\n", (msg))

namespace Patcher {

    // Solution0 will replace the RSA public key stored in main application.
    class Solution0 {
    private:
        static const char Keyword[461];
        static constexpr int KeywordLength = 460;

        std::Tstring InstallationPath;
        std::Tstring MainAppName;
        HANDLE MainAppHandle;
        HANDLE MainAppMappingHandle;
        PVOID MainAppMappingView;
        off_t PatchOffset;
    public:

        Solution0() : InstallationPath(),
                      MainAppName(),
                      MainAppHandle(INVALID_HANDLE_VALUE),
                      MainAppMappingHandle(NULL),
                      MainAppMappingView(nullptr),
                      PatchOffset(-1) {}

        BOOL SetPath(const std::Tstring& Path);

        // Solution0 does not have any requirements for RSA-2048 key
        BOOL CheckKey(RSACipher* cipher) const;

        // Return error code
        // It may return 
        //     ERROR_SUCCESS        (target has been set successfully)
        //     ERROR_FILE_NOT_FOUND (try another name)
        //     ERROR_ACCESS_DENIED  (you need Administrator privilege)
        //     ...
        DWORD TryFile(const std::Tstring& MainAppName);

        // Return error code
        // It may return
        //     ERROR_SUCCESS        (target has been mapped successfully)
        //     ...
        DWORD MapFile();

        // Return TRUE if found, other return FALSE
        BOOL FindPatchOffset();

        // Return error code
        // It may return 
        //     ERROR_SUCCESS        (file has been backed up successfully)
        //     ERROR_FILE_EXISTS    (you should remove backup file first)
        //     ERROR_ACCESS_DENIED  (you need Administrator privilege)
        //     ...
        DWORD BackupFile();

        // Make a patch based on RSA private key
        // Return TRUE if success, otherwise return FALSE
        BOOL MakePatch(RSACipher* cipher);

        // Return error code
        // Return ERROR_SUCCESS if success
        // DWORD GetMainAppVersion(LPDWORD lpMajorVer, LPDWORD lpMinorVer);

        const std::Tstring& GetMainAppName();

        // Close handle returned by CreateFile with a implicit call towards ReleaseMap
        void ReleaseFile();

        // Unmap view returned by MapViewOfFile and 
        // close handle returned by CreateFileMapping
        void ReleaseMap();

        ~Solution0();
    };

    // Solution0 will replace the RSA public key stored in libcc.dll
    class Solution1 {
    private:
        static const char* Keywords[5];
        static const int KeywordsLength[5];

        std::Tstring InstallationPath;
        std::Tstring LibccName;
        HANDLE LibccHandle;
        HANDLE LibccMappingHandle;
        PVOID LibccMappingView;
        off_t PatchOffsets[5];
    public:
        Solution1() : InstallationPath(),
                      LibccName(),
                      LibccHandle(INVALID_HANDLE_VALUE),
                      LibccMappingHandle(NULL),
                      LibccMappingView(nullptr),
                      PatchOffsets{-1, -1, -1, -1, -1} {}

        BOOL SetPath(const std::Tstring& Path);

        // Solution0 does not have any requirements for RSA-2048 key
        BOOL CheckKey(RSACipher* cipher) const;

        // Return error code
        // It may return 
        //     ERROR_SUCCESS        (target has been set successfully)
        //     ERROR_FILE_NOT_FOUND (try another name)
        //     ERROR_ACCESS_DENIED  (you need Administrator privilege)
        //     ...
        DWORD TryFile(const std::Tstring& MainAppName);

        // Return error code
        // It may return
        //     ERROR_SUCCESS        (target has been mapped successfully)
        //     ...
        DWORD MapFile();

        // Return TRUE if found, other return FALSE
        BOOL FindPatchOffset();

        // Return error code
        // It may return 
        //     ERROR_SUCCESS        (file has been backed up successfully)
        //     ERROR_FILE_EXISTS    (you should remove backup file first)
        //     ERROR_ACCESS_DENIED  (you need Administrator privilege)
        //     ...
        DWORD BackupFile();

        // Make a patch based on RSA private key
        // Return TRUE if success, otherwise return FALSE
        BOOL MakePatch(RSACipher* cipher);

        // Close handle returned by CreateFile with a implicit call towards ReleaseMap
        void ReleaseFile();

        // Unmap view returned by MapViewOfFile and 
        // close handle returned by CreateFileMapping
        void ReleaseMap();

        ~Solution1();
    };
}
