#include "def.hpp"

static void help() {
    PRINT_MESSAGE("Usage:");
    PRINT_MESSAGE("    navicat-patcher.exe <Navicat installation path> [RSA-2048 PEM file]");
}

std::Tstring InstallationPath;
std::Tstring MainAppName;
std::Tstring LibccName = TEXT("libcc.dll");

static BOOL SetPath(const std::Tstring& Path) {
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

    InstallationPath = Path;
    if (InstallationPath.back() != TEXT('\\') && InstallationPath.back() != TEXT('/'))
        InstallationPath.push_back(TEXT('/'));  // for Linux compatible

    return TRUE;
}

static DWORD BackupFile(std::Tstring& from, std::Tstring& to) {
    if (::CopyFile(from.c_str(), to.c_str(), TRUE))
        return ERROR_SUCCESS;
    else
        return GetLastError();
}

static BOOL LoadKey(RSACipher* cipher, LPTSTR filename, 
                    Patcher::Solution* pSolution0, 
                    Patcher::Solution* pSolution1) {
    if (filename) {
        std::string PrivateKeyFileName;

        if (!Helper::ConvertToUTF8(filename, PrivateKeyFileName)) {
            REPORT_ERROR("ERROR: ConvertToUTF8 failed.");
            return FALSE;
        }

        if (!cipher->ImportKeyFromFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::PEM>(PrivateKeyFileName)) {
            REPORT_ERROR("ERROR: cipher->ImportKeyFromFile failed.");
            return FALSE;
        }

        if (pSolution0 && !pSolution0->CheckKey(cipher) || 
            pSolution1 && !pSolution1->CheckKey(cipher)) {
            REPORT_ERROR("ERROR: The RSA private key you provide cannot be used.");
            return FALSE;
        }

    } else {
        PRINT_MESSAGE("MESSAGE: Generating new RSA private key, it may take a long time.");

        do {
            cipher->GenerateKey(2048);
        } while (pSolution0 && !pSolution0->CheckKey(cipher) || 
                 pSolution1 && !pSolution1->CheckKey(cipher));   // re-generate RSA key if one of CheckKey return FALSE

        if (!cipher->ExportKeyToFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::NotSpecified>("RegPrivateKey.pem")) {
            REPORT_ERROR("ERROR: Failed to save RSA private key.");
            return FALSE;
        }

        PRINT_MESSAGE("MESSAGE: New RSA private key has been saved to RegPrivateKey.pem.");
    }

    std::string PublicKeyString = cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
    if (PublicKeyString.empty()) {
        REPORT_ERROR("ERROR: cipher->ExportKeyString failed.");
        return FALSE;
    }

    PRINT_MESSAGE("Your RSA public key:");
    PRINT_LPCSTR(PublicKeyString.c_str());
    return TRUE;
}

int _tmain(int argc, TCHAR* argv[]) {
    if (argc != 2 && argc != 3) {
        help();
        return 0;
    }

    RSACipher* cipher = nullptr;
    FileMapper* pMainApp = nullptr;
    FileMapper* pLibcc = nullptr;
    Patcher::Solution* pSolution0 = nullptr;
    Patcher::Solution* pSolution1 = nullptr;
    
    DWORD ErrorCode;

    cipher = RSACipher::Create();
    if (cipher == nullptr) {
        REPORT_ERROR("ERROR: RSACipher::Create failed.");
        goto ON_tmain_ERROR;
    }

    pMainApp = new FileMapper();
    pLibcc = new FileMapper();
    pSolution0 = new Patcher::Solution0();
    pSolution1 = new Patcher::Solution1();

    if (!SetPath(argv[1])) {
        PRINT_MESSAGE("The path you specified:");
        PRINT_LPCTSTR(argv[1]);
        goto ON_tmain_ERROR;
    }

FindMainApp:
    ErrorCode = pMainApp->MapFile(InstallationPath + TEXT("Navicat.exe"));
    if (ErrorCode == ERROR_SUCCESS) {
        MainAppName = TEXT("Navicat.exe");
        PRINT_MESSAGE("MESSAGE: Navicat.exe has been found.");
        goto FindLibcc;
    }
    if (ErrorCode == ERROR_ACCESS_DENIED) {
        PRINT_MESSAGE("ERROR: Cannot open Navicat.exe for ERROR_ACCESS_DENIED.");
        PRINT_MESSAGE("Please re-run with Administrator privilege.");
        goto ON_tmain_ERROR;
    }
    if (ErrorCode != ERROR_FILE_NOT_FOUND) {
        REPORT_ERROR_WITH_CODE("ERROR: Cannot open Navicat.exe.", ErrorCode);
        goto ON_tmain_ERROR;
    }

    ErrorCode = pMainApp->MapFile(InstallationPath + TEXT("Modeler.exe"));
    if (ErrorCode == ERROR_SUCCESS) {
        MainAppName = TEXT("Modeler.exe");
        PRINT_MESSAGE("MESSAGE: Modeler.exe has been found.");
        goto FindLibcc;
    }
    if (ErrorCode == ERROR_ACCESS_DENIED) {
        PRINT_MESSAGE("ERROR: Cannot open Modeler.exe for ERROR_ACCESS_DENIED.");
        PRINT_MESSAGE("Please re-run with Administrator privilege.");
        goto ON_tmain_ERROR;
    }
    if (ErrorCode != ERROR_FILE_NOT_FOUND) {
        REPORT_ERROR_WITH_CODE("ERROR: Cannot open Modeler.exe.", ErrorCode);
        goto ON_tmain_ERROR;
    }

    ErrorCode = pMainApp->MapFile(InstallationPath + TEXT("Rviewer.exe"));
    if (ErrorCode == ERROR_SUCCESS) {
        MainAppName = TEXT("Rviewer.exe");
        PRINT_MESSAGE("MESSAGE: Rviewer.exe has been found.");
        goto FindLibcc;
    }
    if (ErrorCode == ERROR_ACCESS_DENIED) {
        PRINT_MESSAGE("ERROR: Cannot open Rviewer.exe for ERROR_ACCESS_DENIED.");
        PRINT_MESSAGE("Please re-run with Administrator privilege.");
        goto ON_tmain_ERROR;
    }
    if (ErrorCode != ERROR_FILE_NOT_FOUND) {
        REPORT_ERROR_WITH_CODE("ERROR: Cannot open Rviewer.exe.", ErrorCode);
        goto ON_tmain_ERROR;
    }

    PRINT_MESSAGE("ERROR: Cannot find main application. Are you sure the path you specified is correct?");
    PRINT_MESSAGE("The path you specified:");
    PRINT_LPCTSTR(argv[1]);
    goto ON_tmain_ERROR;

FindLibcc:
    ErrorCode = pLibcc->MapFile(InstallationPath + LibccName);
    if (ErrorCode == ERROR_SUCCESS) {
        PRINT_MESSAGE("MESSAGE: libcc.dll has been found.");
    } else if (ErrorCode == ERROR_FILE_NOT_FOUND) {
        PRINT_MESSAGE("MESSAGE: libcc.dll is not found. Solution1 and Solution2 will be omitted.");
        delete pSolution1;
        pSolution1 = nullptr;
        delete pLibcc;
        pLibcc = nullptr;
    } else if (ErrorCode == ERROR_ACCESS_DENIED) {
        PRINT_MESSAGE("ERROR: Cannot open libcc.dll for ERROR_ACCESS_DENIED.");
        PRINT_MESSAGE("Please re-run with Administrator privilege.");
        goto ON_tmain_ERROR;
    } else {
        REPORT_ERROR_WITH_CODE("ERROR: Cannot open libcc.dll.", ErrorCode);
        goto ON_tmain_ERROR;
    }

SearchPublicKey:
    pSolution0->SetFile(pMainApp);
    if (pSolution1) pSolution1->SetFile(pLibcc);

    PRINT_MESSAGE("");
    if (!pSolution0->FindPatchOffset()) {
        _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
        _tprintf_s(TEXT("ERROR: Cannot find RSA public key in %s.\n"), MainAppName.c_str());
        goto ON_tmain_ERROR;
    }

    if (pSolution1 && !pSolution1->FindPatchOffset()) {
        PRINT_MESSAGE("MESSAGE: Cannot find RSA public key in libcc.dll. Solution1 will be omitted.");
        pSolution1->SetFile(nullptr);
        delete pSolution1;
        pSolution1 = nullptr;
    }

LoadingKey:
    PRINT_MESSAGE("");
    if (!LoadKey(cipher, argc == 3 ? argv[2] : nullptr, pSolution0, pSolution1))
        goto ON_tmain_ERROR;

BackupFiles:
    PRINT_MESSAGE("");
    ErrorCode = BackupFile(InstallationPath + MainAppName, InstallationPath + MainAppName + TEXT(".backup"));
    if (ErrorCode == ERROR_SUCCESS) {
        _tprintf_s(TEXT("MESSAGE: %s has been backed up successfully.\n"), MainAppName.c_str());
    } else if (ErrorCode == ERROR_ACCESS_DENIED) {
        _tprintf_s(TEXT("ERROR: Cannot back up %s for ERROR_ACCESS_DENIED.\n"), MainAppName.c_str());
        _tprintf_s(TEXT("Please re-run with Administrator privilege.\n"));
        goto ON_tmain_ERROR;
    } else if (ErrorCode == ERROR_FILE_EXISTS) {
        _tprintf_s(TEXT("ERROR: The backup of %s has been found.\n"), MainAppName.c_str());
        _tprintf_s(TEXT("Please remove %s.backup in Navicat installation path if you're sure %s has not been patched.\n"), 
                   MainAppName.c_str(), 
                   MainAppName.c_str());
        _tprintf_s(TEXT("Otherwise please restore %s by %s.backup and remove %s.backup then try again.\n"), 
                   MainAppName.c_str(),
                   MainAppName.c_str(), 
                   MainAppName.c_str());
        goto ON_tmain_ERROR;
    } else {
        _tprintf_s(TEXT("ERROR: Cannot back up %s. CODE: 0x%08X\n"),
                   MainAppName.c_str(),
                   ErrorCode);
        goto ON_tmain_ERROR;
    }

    if (pSolution1) {
        ErrorCode = BackupFile(InstallationPath + LibccName, InstallationPath + LibccName + TEXT(".backup"));
        if (ErrorCode == ERROR_SUCCESS) {
            PRINT_MESSAGE("MESSAGE: libcc.dll has been backed up successfully.");
        } else if (ErrorCode == ERROR_ACCESS_DENIED) {
            PRINT_MESSAGE("ERROR: Cannot back up libcc.dll for ERROR_ACCESS_DENIED.");
            PRINT_MESSAGE("Please re-run with Administrator privilege.");
            goto ON_tmain_ERROR;
        } else if (ErrorCode == ERROR_FILE_EXISTS) {
            PRINT_MESSAGE("ERROR: The backup of libcc.dll has been found.");
            PRINT_MESSAGE("Please remove libcc.dll.backup in Navicat installation path if you're sure libcc.dll has not been patched.");
            PRINT_MESSAGE("Otherwise please restore libcc.dll by libcc.dll.backup and remove libcc.dll.backup then try again.");
            goto ON_tmain_ERROR;
        } else {
            REPORT_ERROR_WITH_CODE("ERROR: Cannot back up libcc.dll.", ErrorCode);
            goto ON_tmain_ERROR;
        }
    }

MakingPatch:
    PRINT_MESSAGE("");
    if (!pSolution0->MakePatch(cipher))
        goto ON_tmain_ERROR;

    if (pSolution1 && !pSolution1->MakePatch(cipher))
        goto ON_tmain_ERROR;

    PRINT_MESSAGE("Solution0 has been done successfully.");
    if (pSolution1)
        PRINT_MESSAGE("Solution1 has been done successfully.");

ON_tmain_ERROR:
    delete pSolution1;
    delete pSolution0;
    delete pLibcc;
    delete pMainApp;
    delete cipher;
    return 0;
}

