#include "def.hpp"

// The following APIs are in version.lib
// GetFileVersionInfoSize
// GetFileVersionInfo
// VerQueryValue
// #pragma comment(lib, "version.lib")     

namespace Patcher {

    const char Solution0::Keyword[461] =
        "-----BEGIN PUBLIC KEY-----\r\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I\r\n"
        "qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv\r\n"
        "a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF\r\n"
        "R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2\r\n"
        "WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt\r\n"
        "YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ\r\n"
        "awIDAQAB\r\n"
        "-----END PUBLIC KEY-----\r\n";

    BOOL Solution0::SetPath(const std::Tstring& Path) {
        DWORD Attr;

        Attr = GetFileAttributes(Path.c_str());
        if (Attr == INVALID_FILE_ATTRIBUTES) {
            if (GetLastError() == ERROR_INVALID_NAME || GetLastError() == ERROR_FILE_NOT_FOUND) 
                REPORT_ERROR("ERROR: Invalid path. Are you sure the path you specified is correct?");
            else 
                REPORT_ERROR_WITH_CODE("ERROR: GetFileAttributes failed.", GetLastError());
            return FALSE;
        }

        if ((Attr & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            REPORT_ERROR("ERROR: Path is not a directory.");
            return FALSE;
        }

        ReleaseFile();

        InstallationPath = Path;
        if (InstallationPath.back() != TEXT('\\') && InstallationPath.back() != TEXT('/'))
            InstallationPath.push_back(TEXT('/'));  // for Linux compatible

        return TRUE;
    }

    // Solution0 does not have any requirements for RSA-2048 key
    BOOL Solution0::CheckKey(RSACipher* cipher) const {
        return TRUE;
    }

    DWORD Solution0::TryFile(const std::Tstring& Name) {
        std::Tstring MainAppFullName = InstallationPath + Name;
        HANDLE hFile;
        
        hFile = CreateFile(MainAppFullName.c_str(),
                           GENERIC_READ | GENERIC_WRITE, 
                           FILE_SHARE_READ,
                           nullptr,                         // default SA
                           OPEN_EXISTING, 
                           FILE_ATTRIBUTE_NORMAL, 
                           NULL);
        if (hFile == INVALID_HANDLE_VALUE) 
            return GetLastError();

        ReleaseFile();

        MainAppHandle = hFile;
        MainAppName = Name;
        return ERROR_SUCCESS;
    }

    DWORD Solution0::MapFile() {
        DWORD dwLastError = ERROR_SUCCESS;
        HANDLE hMapping = NULL;
        PVOID lpMapView = nullptr;

        hMapping = CreateFileMapping(MainAppHandle,
                                     nullptr,           // default SA
                                     PAGE_READWRITE,
                                     0, 0,              // map all
                                     nullptr);          // we don't need a name
        if (hMapping == NULL) {
            dwLastError = GetLastError();
            goto ON_Solution0_MapFile_ERROR;
        }

        lpMapView = MapViewOfFile(hMapping,
                                  FILE_MAP_READ | FILE_MAP_WRITE,
                                  0, 0, 0);             // map all
        if (lpMapView == nullptr) {
            dwLastError = GetLastError();
            goto ON_Solution0_MapFile_ERROR;
        }

        ReleaseMap();

        MainAppMappingView = lpMapView;
        lpMapView = nullptr;
        MainAppMappingHandle = hMapping;
        hMapping = NULL;

    ON_Solution0_MapFile_ERROR:
        if (hMapping)
            CloseHandle(hMapping);
        return dwLastError;
    }

    BOOL Solution0::FindPatchOffset() {
        BOOL bFound = FALSE;
        DWORD dwFileSize = 0;

        uint8_t* lpFileContent = reinterpret_cast<uint8_t*>(MainAppMappingView);
        dwFileSize = GetFileSize(MainAppHandle, nullptr);
        
        for (DWORD i = 0; i < dwFileSize; ++i) {
            if (memcmp(lpFileContent + i, Keyword, KeywordLength) == 0) {
                PatchOffset = i;
                bFound = TRUE;
                break;
            }
        }

        if (bFound)
            _tprintf_s(TEXT("MESSAGE: [Solution0] Keyword has been found: offset = +0x%08lx.\n"), PatchOffset);
        return bFound;
    }

    DWORD Solution0::BackupFile() {
        std::Tstring TargetFileFullName = InstallationPath + MainAppName;
        std::Tstring BackupFileFullName = InstallationPath + MainAppName + TEXT(".backup");
        
        if (!CopyFile(TargetFileFullName.c_str(), BackupFileFullName.c_str(), TRUE))
            return GetLastError();
        else
            return ERROR_SUCCESS;
    }

    BOOL Solution0::MakePatch(RSACipher* cipher) {
        BOOL bSuccess = FALSE;
        uint8_t* lpFileContent = reinterpret_cast<uint8_t*>(MainAppMappingView);
        std::string RSAPublicKeyPEM;

        RSAPublicKeyPEM = cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
        if (RSAPublicKeyPEM.empty()) {
            REPORT_ERROR("ERROR: cipher->ExportKeyString failed.");
            goto ON_Do_ERROR;
        }

        // lambda function, replace '\n' to '\r\n'
        [](std::string& str, const std::string& OldSub, const std::string& NewSub) {
            std::string::size_type pos = 0;
            std::string::size_type srclen = OldSub.size();
            std::string::size_type dstlen = NewSub.size();

            while ((pos = str.find(OldSub, pos)) != std::string::npos) {
                str.replace(pos, srclen, NewSub);
                pos += dstlen;
            }
        } (RSAPublicKeyPEM, "\n", "\r\n");

        if (RSAPublicKeyPEM.length() != KeywordLength) {
            REPORT_ERROR("ERROR: Public key length does not match.");
            goto ON_Do_ERROR;
        }

        _tprintf_s(TEXT("@%s+0x%08X\nPrevious:\n"), MainAppName.c_str(), PatchOffset);
        Helper::PrintMemory(lpFileContent + PatchOffset,
                            lpFileContent + PatchOffset + KeywordLength, 
                            lpFileContent);

        memcpy(lpFileContent + PatchOffset, RSAPublicKeyPEM.c_str(), KeywordLength);

        PRINT_MESSAGE("After:");
        Helper::PrintMemory(lpFileContent + PatchOffset,
                            lpFileContent + PatchOffset + KeywordLength,
                            lpFileContent);
        PRINT_MESSAGE("");

        bSuccess = TRUE;
    ON_Do_ERROR:
        return bSuccess;
    }

//     DWORD Solution0::GetMainAppVersion(LPDWORD lpMajorVer, LPDWORD lpMinorVer) {
//         BOOL bSuccess = FALSE;
//         DWORD dwLastError = ERROR_SUCCESS;
//         std::Tstring TargetFileFullName = InstallationPath + MainAppName;
// 
//         DWORD dwSize = 0;
//         PVOID lpData = NULL;
//         VS_FIXEDFILEINFO* lpVersionInfo = NULL;
//         UINT VersionInfoSize = 0;
// 
//         dwSize = GetFileVersionInfoSize(TargetFileFullName.c_str(), 
//                                         &dwSize);   // MSDN doesn't say it can be NULL.
//                                                     // so I use dwSize to receive this deprecated value
//         if (dwSize == 0) {
//             dwLastError = GetLastError();
//             REPORT_ERROR_WITH_CODE("ERROR: GetFileVersionInfoSize failed.", dwLastError);
//             goto ON_Solution0_GetMainAppVersion_ERROR;
//         }
// 
//         lpData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
//         if (lpData == nullptr) {
//             dwLastError = GetLastError();
//             REPORT_ERROR_WITH_CODE("ERROR: HeapAlloc failed.", dwLastError);
//             goto ON_Solution0_GetMainAppVersion_ERROR;
//         }
// 
//         if (!GetFileVersionInfo(TargetFileFullName.c_str(), NULL, dwSize, lpData)) {
//             dwLastError = GetLastError();
//             REPORT_ERROR_WITH_CODE("ERROR: GetFileVersionInfo failed.", dwLastError);
//             goto ON_Solution0_GetMainAppVersion_ERROR;
//         }
// 
//         if (!VerQueryValue(lpData, TEXT("\\"), reinterpret_cast<LPVOID*>(&lpVersionInfo), &VersionInfoSize)) {
//             dwLastError = GetLastError();
//             REPORT_ERROR_WITH_CODE("ERROR: VerQueryValue failed.", dwLastError);
//             goto ON_Solution0_GetMainAppVersion_ERROR;
//         }
// 
//         *lpMajorVer = lpVersionInfo->dwProductVersionMS;
//         *lpMinorVer = lpVersionInfo->dwProductVersionLS;
// 
//         bSuccess = TRUE;
//     ON_Solution0_GetMainAppVersion_ERROR:
//         if (lpData)
//             HeapFree(GetProcessHeap(), NULL, lpData);
//         return bSuccess;
//     }

    const std::Tstring& Solution0::GetMainAppName() {
        return MainAppName;
    }

    void Solution0::ReleaseFile() {
        ReleaseMap();

        if (MainAppHandle != INVALID_HANDLE_VALUE && MainAppHandle) {
            CloseHandle(MainAppHandle);
            MainAppHandle = INVALID_HANDLE_VALUE;
        }
    }

    void Solution0::ReleaseMap() {
        if (MainAppMappingView) {
            UnmapViewOfFile(MainAppMappingView);
            MainAppMappingView = nullptr;
        }

        if (MainAppMappingHandle) {
            CloseHandle(MainAppMappingHandle);
            MainAppMappingHandle = NULL;
        }
    }

    Solution0::~Solution0() {
        ReleaseFile();
    }
}
