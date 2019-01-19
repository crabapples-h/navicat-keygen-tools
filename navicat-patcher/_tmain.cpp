#include <tchar.h>
#include <windows.h>
#include "Exception.hpp"
#include "PatchSolution.hpp"
#include "Helper.hpp"

#undef __BASE_FILE__
#define __BASE_FILE__ "_tmain.cpp"

#define PRINT_MESSAGE_LITERAL(m) _putts(TEXT(m))
#define PRINT_PTSTR(m) _putts(m)
#define PRINT_PCSTR(m)  puts(m)
#define PRINT_PCWSTR(m) _putws(m)

String InstallationPath;
String MainAppName;
String LibccName = TEXT("libcc.dll");

static void Welcome() {
    PRINT_MESSAGE_LITERAL("***************************************************");
    PRINT_MESSAGE_LITERAL("*       Navicat Patcher by @DoubleLabyrinth       *");
          _tprintf_s(TEXT("*           Release date: %-24s*\n"), TEXT(__DATE__));
    PRINT_MESSAGE_LITERAL("***************************************************");
    PRINT_MESSAGE_LITERAL("");
    PRINT_MESSAGE_LITERAL("Press Enter to continue or Ctrl + C to abort.");
    _gettchar();
}

static void Help() {
    PRINT_MESSAGE_LITERAL("Usage:");
    PRINT_MESSAGE_LITERAL("    navicat-patcher.exe <Navicat installation path> [RSA-2048 PEM file]");
}

static void SetPath(PTSTR pszPath) {
    DWORD Attr;

    Attr = GetFileAttributes(pszPath);
    if (Attr == INVALID_FILE_ATTRIBUTES)
        throw SystemError(__BASE_FILE__, __LINE__, GetLastError(), 
                          "GetFileAttributes fails.");

    if ((Attr & FILE_ATTRIBUTE_DIRECTORY) == 0)
        throw Exception(__BASE_FILE__, __LINE__, 
                        "Path does not point to a directory.");

    InstallationPath = pszPath;
    if (InstallationPath.back() != TEXT('\\') && InstallationPath.back() != TEXT('/'))
        InstallationPath.push_back(TEXT('/'));  // for Linux compatible
}

static void BackupFile(const String& From, const String& To) {
    if (::CopyFile(From.c_str(), To.c_str(), TRUE) == FALSE)
        throw SystemError(__BASE_FILE__, __LINE__, GetLastError(), 
                          "CopyFile fails.");
}

static void LoadKey(RSACipher* pCipher, PTSTR FileName, 
                    PatchSolution* pSolution0,
                    PatchSolution* pSolution1, 
                    PatchSolution* pSolution2, 
                    PatchSolution* pSolution3) {
    if (FileName) {
        std::string PrivateKeyFileName = Helper::ConvertToUTF8(FileName);

        pCipher->ImportKeyFromFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::PEM>(PrivateKeyFileName);

        if (pSolution0 && !pSolution0->CheckKey(pCipher) ||
            pSolution1 && !pSolution1->CheckKey(pCipher) ||
            pSolution2 && !pSolution2->CheckKey(pCipher) ||
            pSolution3 && !pSolution3->CheckKey(pCipher))
            throw Exception(__BASE_FILE__, __LINE__, 
                            "The RSA private key you provide cannot be used.");
    } else {
        PRINT_MESSAGE_LITERAL("MESSAGE: Generating new RSA private key, it may take a long time.");

        do {
            pCipher->GenerateKey(2048);
        } while (pSolution0 && !pSolution0->CheckKey(pCipher) ||
                 pSolution1 && !pSolution1->CheckKey(pCipher) ||
                 pSolution2 && !pSolution2->CheckKey(pCipher) ||
                 pSolution3 && !pSolution3->CheckKey(pCipher));   // re-generate RSA key if CheckKey return false

        pCipher->ExportKeyToFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::NotSpecified>("RegPrivateKey.pem");

        PRINT_MESSAGE_LITERAL("MESSAGE: New RSA private key has been saved to RegPrivateKey.pem.");
    }

    std::string PublicKeyString = pCipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();

    PRINT_MESSAGE_LITERAL("");
    PRINT_MESSAGE_LITERAL("Your RSA public key:");
    PRINT_PCSTR(PublicKeyString.c_str());
}

static void ExceptionReport(const Exception& e) noexcept {
    printf_s("ERROR: @ %s - Line %d\n", e.SourceFile(), e.SourceLine());
    if (e.HasErrorCode()) {
        const char* aa = e.ErrorString();
        printf_s("ErrorCode = 0x%08lx\n", e.ErrorCode());
        printf_s("ErrorString: %s\n", e.ErrorString());
    } else {
        printf_s("%s\n", e.CustomMessage());
    }
}

int _tmain(int argc, PTSTR argv[]) {
    if (argc != 2 && argc != 3) {
        Help();
        return 0;
    }

    Welcome();

    ResourceGuard<CppObjectTraits<RSACipher>> pCipher;
    ResourceGuard<CppObjectTraits<FileMapper>> pMainExe;
    ResourceGuard<CppObjectTraits<FileMapper>> pLibccDLL;
    ResourceGuard<CppObjectTraits<PatchSolution>> pSolution0;
    ResourceGuard<CppObjectTraits<PatchSolution>> pSolution1;
    ResourceGuard<CppObjectTraits<PatchSolution>> pSolution2;
    ResourceGuard<CppObjectTraits<PatchSolution>> pSolution3;

    try {
        SetPath(argv[1]);
    } catch (Exception& e) {
        ExceptionReport(e);
        PRINT_MESSAGE_LITERAL("Are you sure the path you specified is correct?");
        PRINT_MESSAGE_LITERAL("The path you specified:");
        PRINT_PTSTR(argv[1]);
        return 0;
    }

    pCipher.TakeHoldOf(new RSACipher());

    // -----------------
    //  Map files
    // -----------------
    do {
        pLibccDLL.TakeHoldOf(new FileMapper());
        try {
            pLibccDLL.GetHandle()->MapFile(InstallationPath + TEXT("libcc.dll"));
            break;
        } catch (Exception& e) {
            if (!e.HasErrorCode() || e.ErrorCode() != ERROR_FILE_NOT_FOUND) {
                ExceptionReport(e);
                if (e.HasErrorCode() && e.ErrorCode() == ERROR_ACCESS_DENIED)
                    PRINT_MESSAGE_LITERAL("Please re-run with Administrator privilege.");
                return 0;
            }
        }
        pLibccDLL.Release();

        pMainExe.TakeHoldOf(new FileMapper());
        try {
            pMainExe.GetHandle()->MapFile(InstallationPath + TEXT("Navicat.exe"));
            MainAppName = TEXT("Navicat.exe");
            break;
        } catch (Exception& e) {
            if (!e.HasErrorCode() || e.ErrorCode() != ERROR_FILE_NOT_FOUND) {
                ExceptionReport(e);
                if (e.HasErrorCode() && e.ErrorCode() == ERROR_ACCESS_DENIED)
                    PRINT_MESSAGE_LITERAL("Please re-run with Administrator privilege.");
                return 0;
            }
        }

        try {
            pMainExe.GetHandle()->MapFile(InstallationPath + TEXT("Modeler.exe"));
            MainAppName = TEXT("Modeler.exe");
            break;
        } catch (Exception& e) {
            if (!e.HasErrorCode() || e.ErrorCode() != ERROR_FILE_NOT_FOUND) {
                ExceptionReport(e);
                if (e.HasErrorCode() && e.ErrorCode() == ERROR_ACCESS_DENIED)
                    PRINT_MESSAGE_LITERAL("Please re-run with Administrator privilege.");
                return 0;
            }
        }

        try {
            pMainExe.GetHandle()->MapFile(InstallationPath + TEXT("Rviewer.exe"));
            MainAppName = TEXT("Rviewer.exe");
            break;
        } catch (Exception& e) {
            if (!e.HasErrorCode() || e.ErrorCode() != ERROR_FILE_NOT_FOUND) {
                ExceptionReport(e);
                if (e.HasErrorCode() && e.ErrorCode() == ERROR_ACCESS_DENIED)
                    PRINT_MESSAGE_LITERAL("Please re-run with Administrator privilege.");
                return 0;
            }
        }
        pMainExe.Release();
    } while (false);

    // -----------
    //  decide PatchSolutions
    // -----------

    if (pMainExe.IsValid()) {
        try {
            pSolution0.TakeHoldOf(new PatchSolution0());
            pSolution0.GetHandle()->SetFile(pMainExe);
            if (pSolution0.GetHandle()->FindPatchOffset() == false) {
                PRINT_MESSAGE_LITERAL("MESSAGE: PatchSolution0 will be omitted.");
                pSolution0.Release();
            }
            PRINT_MESSAGE_LITERAL("");
        } catch (Exception& e) {
            ExceptionReport(e);
            return 0;
        }
    } else {
        PRINT_MESSAGE_LITERAL("MESSAGE: PatchSolution0 will be omitted.");
        PRINT_MESSAGE_LITERAL("");
    }

    if (pLibccDLL.IsValid()) {
        try {
            pSolution3.TakeHoldOf(new PatchSolution3());
            pSolution3.GetHandle()->SetFile(pLibccDLL);
            if (pSolution3.GetHandle()->FindPatchOffset() == false) {
                PRINT_MESSAGE_LITERAL("MESSAGE: PatchSolution3 will be omitted.");
                pSolution3.Release();
            }
            PRINT_MESSAGE_LITERAL("");

            pSolution2.TakeHoldOf(new PatchSolution2());
            pSolution2.GetHandle()->SetFile(pLibccDLL);
            if (pSolution2.GetHandle()->FindPatchOffset() == false) {
                PRINT_MESSAGE_LITERAL("MESSAGE: PatchSolution2 will be omitted.");
                pSolution2.Release();
            }
            PRINT_MESSAGE_LITERAL("");

            pSolution1.TakeHoldOf(new PatchSolution1());
            pSolution1.GetHandle()->SetFile(pLibccDLL);
            if (pSolution1.GetHandle()->FindPatchOffset() == false) {
                PRINT_MESSAGE_LITERAL("MESSAGE: PatchSolution1 will be omitted.");
                pSolution2.Release();
            }
            PRINT_MESSAGE_LITERAL("");
        } catch (Exception& e) {
            ExceptionReport(e);
            return 0;
        }
    } else {
        PRINT_MESSAGE_LITERAL("MESSAGE: PatchSolution3 will be omitted.");
        PRINT_MESSAGE_LITERAL("MESSAGE: PatchSolution2 will be omitted.");
        PRINT_MESSAGE_LITERAL("MESSAGE: PatchSolution1 will be omitted.");
        PRINT_MESSAGE_LITERAL("");
    }

    if (pSolution0.IsValid() == false)
        pMainExe.Release();

    if (pSolution1.IsValid() == false && pSolution2.IsValid() == false && pSolution3.IsValid() == false)
        pLibccDLL.Release();

    if (pSolution0.IsValid() == false &&
        pSolution1.IsValid() == false &&
        pSolution2.IsValid() == false &&
        pSolution3.IsValid() == false) 
    {
        PRINT_MESSAGE_LITERAL("");
        PRINT_MESSAGE_LITERAL("ERROR: Cannot find RSA public key.");
        PRINT_MESSAGE_LITERAL("Are you sure your Navicat has not been patched before?");
        return 0;
    }

    // -------------
    //  LoadKey
    // -------------
    try {
        LoadKey(pCipher,
                argc == 3 ? argv[2] : nullptr,
                pSolution0,
                pSolution1,
                pSolution2,
                pSolution3);
    } catch (Exception& e) {
        ExceptionReport(e);
        return 0;
    }

    // -------------
    //  BackupFile
    // -------------
    try {
        if (pMainExe.IsValid())
            BackupFile(InstallationPath + MainAppName, InstallationPath + MainAppName + TEXT(".backup"));
    } catch (Exception& e) {
        ExceptionReport(e);
        if (e.HasErrorCode() && e.ErrorCode() == ERROR_FILE_EXISTS) {
            _tprintf_s(TEXT("The backup of %s has been found.\n"), MainAppName.c_str());
            _tprintf_s(TEXT("Please remove %s.backup in Navicat installation path if you're sure %s has not been patched.\n"),
                       MainAppName.c_str(),
                       MainAppName.c_str());
            _tprintf_s(TEXT("Otherwise please restore %s by %s.backup and remove %s.backup then try again.\n"),
                       MainAppName.c_str(),
                       MainAppName.c_str(),
                       MainAppName.c_str());
        }
        return 0;
    }

    try {
        if (pLibccDLL.IsValid())
            BackupFile(InstallationPath + LibccName, InstallationPath + LibccName + TEXT(".backup"));
    } catch (Exception& e) {
        ExceptionReport(e);
        if (e.HasErrorCode() && e.ErrorCode() == ERROR_FILE_EXISTS) {
            _tprintf_s(TEXT("The backup of %s has been found.\n"), LibccName.c_str());
            _tprintf_s(TEXT("Please remove %s.backup in Navicat installation path if you're sure %s has not been patched.\n"),
                       LibccName.c_str(),
                       LibccName.c_str());
            _tprintf_s(TEXT("Otherwise please restore %s by %s.backup and remove %s.backup then try again.\n"),
                       LibccName.c_str(),
                       LibccName.c_str(),
                       LibccName.c_str());
        }
        return 0;
    }

    // -------------
    //  MakePatch
    // -------------
    try {
        if (pSolution3.IsValid()) {
            pSolution3.GetHandle()->MakePatch(pCipher);
            PRINT_MESSAGE_LITERAL("");
        }
        if (pSolution2.IsValid()) {
            pSolution2.GetHandle()->MakePatch(pCipher);
            PRINT_MESSAGE_LITERAL("");
        }
        if (pSolution1.IsValid()) {
            pSolution1.GetHandle()->MakePatch(pCipher);
            PRINT_MESSAGE_LITERAL("");
        }
        if (pSolution0.IsValid()) {
            pSolution0.GetHandle()->MakePatch(pCipher);
            PRINT_MESSAGE_LITERAL("");
        }
    } catch (Exception& e) {
        ExceptionReport(e);
        return 0;
    }

    PRINT_MESSAGE_LITERAL("MESSAGE: Patch has been done successfully.");
    return 0;
}

