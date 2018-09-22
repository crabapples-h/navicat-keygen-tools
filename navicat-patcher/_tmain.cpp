#include "def.hpp"

static void help() {
    PRINT_MESSAGE("Usage:");
    PRINT_MESSAGE("    navicat-patcher.exe <Navicat installation path> [RSA-2048 PEM file]");
}

static BOOL LoadKey(RSACipher* cipher, LPTSTR filename, Patcher::Solution0* pSolution0, Patcher::Solution1* pSolution1) {
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
    Patcher::Solution0* pSolution0 = nullptr;
    Patcher::Solution1* pSolution1 = nullptr;
    
    DWORD ErrorCode;

    cipher = RSACipher::Create();
    if (cipher == nullptr) {
        REPORT_ERROR("ERROR: RSACipher::Create failed.");
        goto ON_tmain_ERROR;
    }

    pSolution0 = new Patcher::Solution0();
    pSolution1 = new Patcher::Solution1();

    if (!pSolution0->SetPath(argv[1])) {
        PRINT_MESSAGE("The path you specified:");
        PRINT_LPCTSTR(argv[1]);
        goto ON_tmain_ERROR;
    }
    if (!pSolution1->SetPath(argv[1])) {
        PRINT_MESSAGE("The path you specified:");
        PRINT_LPCTSTR(argv[1]);
        goto ON_tmain_ERROR;
    }

FindMainApp:
    ErrorCode = pSolution0->TryFile(TEXT("Navicat.exe"));
    if (ErrorCode == ERROR_SUCCESS) {
        PRINT_MESSAGE("MESSAGE: Navicat.exe has been found.");
        goto FindLibcc;
    }else if (ErrorCode == ERROR_ACCESS_DENIED) {
        PRINT_MESSAGE("ERROR: Cannot open Navicat.exe for ERROR_ACCESS_DENIED.");
        PRINT_MESSAGE("Please re-run with Administrator privilege.");
        goto ON_tmain_ERROR;
    }
    if (ErrorCode != ERROR_FILE_NOT_FOUND) {
        REPORT_ERROR_WITH_CODE("ERROR: Cannot open Navicat.exe.", ErrorCode);
        goto ON_tmain_ERROR;
    }

    ErrorCode = pSolution0->TryFile(TEXT("Modeler.exe"));
    if (ErrorCode == ERROR_SUCCESS) {
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

    ErrorCode = pSolution0->TryFile(TEXT("Rviewer.exe"));
    if (ErrorCode == ERROR_SUCCESS) {
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
    ErrorCode = pSolution1->TryFile(TEXT("libcc.dll"));
    if (ErrorCode == ERROR_SUCCESS) {
        PRINT_MESSAGE("MESSAGE: libcc.dll has been found.");
    } else if (ErrorCode == ERROR_FILE_NOT_FOUND) {
        PRINT_MESSAGE("MESSAGE: libcc.dll is not found. Solution1 will be omitted.");
        delete pSolution1;
        pSolution1 = nullptr;
    } else if (ErrorCode == ERROR_ACCESS_DENIED) {
        PRINT_MESSAGE("ERROR: Cannot open libcc.dll for ERROR_ACCESS_DENIED.");
        PRINT_MESSAGE("Please re-run with Administrator privilege.");
        goto ON_tmain_ERROR;
    } else {
        REPORT_ERROR_WITH_CODE("ERROR: Cannot open libcc.dll.", ErrorCode);
        goto ON_tmain_ERROR;
    }

SearchPublicKey:
    PRINT_MESSAGE("");
    ErrorCode = pSolution0->MapFile();
    if (ErrorCode != ERROR_SUCCESS) {
        _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
        _tprintf_s(TEXT("ERROR: Cannot map %s. CODE: 0x%08X\n"), 
                   pSolution0->GetMainAppName().c_str(), 
                   ErrorCode);
        goto ON_tmain_ERROR;
    }
    if (!pSolution0->FindPatchOffset()) {
        _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
        _tprintf_s(TEXT("ERROR: Cannot find RSA public key in %s.\n"),
                   pSolution0->GetMainAppName().c_str());
        goto ON_tmain_ERROR;
    }

    if (pSolution1) {
        ErrorCode = pSolution1->MapFile();
        if (ErrorCode != ERROR_SUCCESS) {
            REPORT_ERROR_WITH_CODE("ERROR: Cannot map libcc.dll.", ErrorCode);
            goto ON_tmain_ERROR;
        }
        if (!pSolution1->FindPatchOffset()) {
            PRINT_MESSAGE("MESSAGE: Cannot find RSA public key in libcc.dll. Solution1 will be omitted.");
            delete pSolution1;
            pSolution1 = nullptr;
        }
    }

LoadingKey:
    PRINT_MESSAGE("");
    if (!LoadKey(cipher, argc == 3 ? argv[2] : nullptr, pSolution0, pSolution1))
        goto ON_tmain_ERROR;

BackupFiles:
    PRINT_MESSAGE("");
    ErrorCode = pSolution0->BackupFile();
    if (ErrorCode == ERROR_SUCCESS) {
        _tprintf_s(TEXT("MESSAGE: %s has been backed up successfully.\n"), 
                   pSolution0->GetMainAppName().c_str());
    } else if (ErrorCode == ERROR_ACCESS_DENIED) {
        _tprintf_s(TEXT("ERROR: Cannot back up %s for ERROR_ACCESS_DENIED.\n"), 
                   pSolution0->GetMainAppName().c_str());
        _tprintf_s(TEXT("Please re-run with Administrator privilege.\n"));
        goto ON_tmain_ERROR;
    } else if (ErrorCode == ERROR_FILE_EXISTS) {
        _tprintf_s(TEXT("ERROR: The backup of %s has been found.\n"), 
                   pSolution0->GetMainAppName().c_str());
        _tprintf_s(TEXT("Please remove %s.backup in Navicat installation path if you're sure %s has not been patched.\n"), 
                   pSolution0->GetMainAppName().c_str(), 
                   pSolution0->GetMainAppName().c_str());
        _tprintf_s(TEXT("Otherwise please restore %s by %s.backup and remove %s.backup then try again.\n"), 
                   pSolution0->GetMainAppName().c_str(),
                   pSolution0->GetMainAppName().c_str(), 
                   pSolution0->GetMainAppName().c_str());
        goto ON_tmain_ERROR;
    } else {
        _tprintf_s(TEXT("ERROR: Cannot back up %s. CODE: 0x%08X\n"),
                   pSolution0->GetMainAppName().c_str(),
                   ErrorCode);
        goto ON_tmain_ERROR;
    }

    if (pSolution1) {
        ErrorCode = pSolution1->BackupFile();
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
    delete cipher;
    return 0;
}