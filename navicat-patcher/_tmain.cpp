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
String LibccName = TEXT("libcc.dll");

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

static void LoadKey(RSACipher* cipher, PTSTR FileName, PatchSolution* pSolution) {
    if (FileName) {
        std::string PrivateKeyFileName = Helper::ConvertToUTF8(FileName);

        cipher->ImportKeyFromFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::PEM>(PrivateKeyFileName);

        if (pSolution && !pSolution->CheckKey(cipher))
            throw Exception(__BASE_FILE__, __LINE__, 
                            "The RSA private key you provide cannot be used.");
    } else {
        PRINT_MESSAGE_LITERAL("MESSAGE: Generating new RSA private key, it may take a long time.");

        do {
            cipher->GenerateKey(2048);
        } while (pSolution && !pSolution->CheckKey(cipher));   // re-generate RSA key if CheckKey return false

        cipher->ExportKeyToFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::NotSpecified>("RegPrivateKey.pem");

        PRINT_MESSAGE_LITERAL("MESSAGE: New RSA private key has been saved to RegPrivateKey.pem.");
    }

    std::string PublicKeyString = cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();

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

    ResourceGuard<CppObjectTraits<RSACipher>> pCipher;
    ResourceGuard<CppObjectTraits<FileMapper>> pLibccDLL;
    ResourceGuard<CppObjectTraits<PatchSolution>> pSolution;

    try {
        pCipher.TakeHoldOf(new RSACipher());
        pLibccDLL.TakeHoldOf(new FileMapper());
        pSolution.TakeHoldOf(new PatchSolution3());
    } catch (Exception& e) {
        ExceptionReport(e);
        return 0;
    }

    try {
        SetPath(argv[1]);
    } catch (Exception& e) {
        ExceptionReport(e);
        PRINT_MESSAGE_LITERAL("Are you sure the path you specified is correct?");
        PRINT_MESSAGE_LITERAL("The path you specified:");
        PRINT_PTSTR(argv[1]);
        return 0;
    }

    try {
        pLibccDLL.GetHandle()->MapFile(InstallationPath + LibccName);
    } catch (Exception& e) {
        ExceptionReport(e);
        if (e.HasErrorCode() && e.ErrorCode() == ERROR_ACCESS_DENIED)
            PRINT_MESSAGE_LITERAL("Please re-run with Administrator privilege.");
        return 0;
    }

    pSolution.GetHandle()->SetFile(pLibccDLL);
    if (!pSolution.GetHandle()->FindPatchOffset()) {
        PRINT_MESSAGE_LITERAL("ERROR: Cannot find RSA public key in libcc.dll");
        PRINT_MESSAGE_LITERAL("Are you sure that libcc.dll has not been patched before?");
        return 0;
    }

    PRINT_MESSAGE_LITERAL("");

    try {
        LoadKey(pCipher, argc == 3 ? argv[2] : nullptr, pSolution);
        BackupFile(InstallationPath + LibccName, InstallationPath + LibccName + TEXT(".backup"));
        pSolution.GetHandle()->MakePatch(pCipher);
    } catch (Exception& e) {
        ExceptionReport(e);
        return 0;
    }

    PRINT_MESSAGE_LITERAL("");
    PRINT_MESSAGE_LITERAL("MESSAGE: Patch has been done successfully.");
    return 0;
}

