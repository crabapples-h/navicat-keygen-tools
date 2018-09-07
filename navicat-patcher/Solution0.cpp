#include "def.hpp"

// Solution0 is for navicat premium of which the version < 12.0.25
namespace patcher::Solution0 {

    static std::Tstring InstallationPath;

    static const CHAR Keyword[] =
        "-----BEGIN PUBLIC KEY-----\r\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I\r\n"
        "qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv\r\n"
        "a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF\r\n"
        "R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2\r\n"
        "WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt\r\n"
        "YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ\r\n"
        "awIDAQAB\r\n"
        "-----END PUBLIC KEY-----\r\n";

    static const DWORD KeywordLength = sizeof(Keyword) - 1;

    static LPCTSTR PossibleName[3] = {
        TEXT("Navicat.exe"),    // for Linux compatible, main program name is "Navicat.exe" in Linux, case sensitive
        TEXT("Modeler.exe"),    // for Linux compatible
        TEXT("Rviewer.exe")     // for Linux compatible
    };

    static LPCTSTR TargetName = NULL;

    static HMODULE hTarget = NULL;

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
        return TRUE;
    }

    BOOL FindTargetFile() {
        BOOL bSuccess = FALSE;
        DWORD dwLastError = ERROR_SUCCESS;

        for (size_t i = 0; i < _countof(PossibleName); ++i) {
            std::Tstring&& PossibleFileName = InstallationPath + PossibleName[i];
            
            hTarget = LoadLibrary(PossibleFileName.c_str());
            if (hTarget == NULL && (dwLastError = GetLastError()) != ERROR_MOD_NOT_FOUND) {
                _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
                _tprintf_s(TEXT("Unexpected Error @ LoadLibrary. CODE: 0x%08X\n"), dwLastError);
                goto ON_FindTargetFile_ERROR;
            }
            if (hTarget) {
                _tprintf_s(TEXT("Target has been found: %s\n"), PossibleName[i]);
                TargetName = PossibleName[i];
                bSuccess = TRUE;
                goto ON_FindTargetFile_ERROR;
            }
        }

    ON_FindTargetFile_ERROR:
        return bSuccess;
    }

    BOOL CheckFile() {
        BOOL bFound = FALSE;
        DWORD dwLastError = ERROR_SUCCESS;
        HRSRC hRes = NULL;
        HGLOBAL hGLobal = NULL;
        PVOID lpData = NULL;
        DWORD dwSize = 0;

        if (hTarget == NULL) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Error: Target has not been set yet.\n"));
            goto ON_CheckFile_ERROR;
        }

        hRes = FindResource(hTarget, TEXT("ACTIVATIONPUBKEY"), RT_RCDATA);
        if (hRes == NULL) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ FindResource. CODE: 0x%08X\n"), dwLastError);
            goto ON_CheckFile_ERROR;
        }

        hGLobal = LoadResource(hTarget, hRes);
        if (hGLobal == NULL) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ LoadResource. CODE: 0x%08X\n"), dwLastError);
            goto ON_CheckFile_ERROR;
        }

        lpData = LockResource(hGLobal);
        if (lpData == NULL) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ LockResource. CODE: 0x%08X\n"), dwLastError);
            goto ON_CheckFile_ERROR;
        }

        dwSize = SizeofResource(hTarget, hRes);
        if (dwSize == 0) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ SizeofResource. CODE: 0x%08X\n"), dwLastError);
            goto ON_CheckFile_ERROR;
        }

        if (dwSize == KeywordLength && memcmp(lpData, Keyword, KeywordLength) == 0) {
            FreeLibrary(hTarget);
            hTarget = NULL;
            bFound = TRUE;
        } else {
            FreeLibrary(hTarget);
            hTarget = NULL;
            TargetName = NULL;
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: Resource doest not match.\n"));
            goto ON_CheckFile_ERROR;
        }

    ON_CheckFile_ERROR:
        return bFound;
    }

    BOOL BackupFile() {
        BOOL bSuccess = FALSE;
        DWORD dwLastError = ERROR_SUCCESS;
        std::Tstring&& TargetFileName = InstallationPath + TargetName;
        std::Tstring&& BackupFileName = InstallationPath + TargetName + TEXT(".backup");

        if (!CopyFile(TargetFileName.c_str(), BackupFileName.c_str(), TRUE)) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ CopyFile. CODE: 0x%08X\n"), dwLastError);
            goto ON_BackupFile_ERROR;
        }

        bSuccess = TRUE;
    ON_BackupFile_ERROR:
        return bSuccess;
    }

    BOOL Do(RSACipher* cipher) {
        BOOL bSuccess = FALSE;
        DWORD dwLastError = ERROR_SUCCESS;
        std::string RSAPublicKeyPEM;
        std::Tstring&& TargetFileName = InstallationPath + TargetName;
        HANDLE hUpdater = NULL;

        RSAPublicKeyPEM = cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
        if (RSAPublicKeyPEM.empty()) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: cipher->ExportKeyString failed.\n"));
            goto ON_Do_ERROR;
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

        if (RSAPublicKeyPEM.length() != KeywordLength) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: Public key length does not match.\n"));
            goto ON_Do_ERROR;
        }

        hUpdater = BeginUpdateResource(TargetFileName.c_str(), FALSE);
        if (hUpdater == NULL) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ BeginUpdateResource. CODE: 0x%08X\n"), dwLastError);
            goto ON_Do_ERROR;
        }

        if (!UpdateResource(hUpdater,
                            RT_RCDATA,
                            TEXT("ACTIVATIONPUBKEY"),
                            MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                            (LPVOID)RSAPublicKeyPEM.c_str(), 
                            KeywordLength)) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ UpdateResource. CODE: 0x%08X\n"), dwLastError);
            goto ON_Do_ERROR;
        } 
        
        bSuccess = TRUE;

    ON_Do_ERROR:
        EndUpdateResource(hUpdater, !bSuccess);
        return bSuccess;
    }

    BOOL GetVersion(LPDWORD lpMajorVer, LPDWORD lpMinorVer) {
        BOOL bSuccess = FALSE;
        DWORD dwLastError = ERROR_SUCCESS;
        std::Tstring&& TargetFileName = InstallationPath + TargetName;
        DWORD dwSize = 0;
        PVOID lpData = NULL;
        VS_FIXEDFILEINFO* lpVersionInfo = NULL;
        UINT VersionInfoSize = 0;

        dwSize = GetFileVersionInfoSize(TargetFileName.c_str(), 
                                        &dwSize);   // MSDN doesn't say it can be NULL.
                                                    // so I use dwSize to receive this deprecated value
        if (dwSize == 0) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ GetFileVersionInfoSize. CODE: 0x%08X\n"), dwLastError);
            goto ON_GetVersion_ERROR;
        }

        lpData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (lpData == NULL) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ HeapAlloc. CODE: 0x%08X\n"), dwLastError);
            goto ON_GetVersion_ERROR;
        }

        if (!GetFileVersionInfo(TargetFileName.c_str(), NULL, dwSize, lpData)) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ GetFileVersionInfo. CODE: 0x%08X\n"), dwLastError);
            goto ON_GetVersion_ERROR;
        }

        if (!VerQueryValue(lpData, TEXT("\\"), (LPVOID*)&lpVersionInfo, &VersionInfoSize)) {
            dwLastError = GetLastError();
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("Failed @ VerQueryValue. CODE: 0x%08X\n"), dwLastError);
            goto ON_GetVersion_ERROR;
        }

        *lpMajorVer = lpVersionInfo->dwProductVersionMS;
        *lpMinorVer = lpVersionInfo->dwProductVersionLS;
        bSuccess = TRUE;

    ON_GetVersion_ERROR:
        if (lpData)
            HeapFree(GetProcessHeap(), NULL, lpData);
        return bSuccess;
    }

    VOID Finalize() {
        if (hTarget) {
            FreeLibrary(hTarget);
            hTarget = NULL;
        }
    }
}
