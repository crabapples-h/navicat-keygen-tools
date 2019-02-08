#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "PatchSolutions.hpp"

static void Welcome() {
    puts("***************************************************");
    puts("*       Navicat Patcher by @DoubleLabyrinth       *");
    puts("*                  Version: 3.0                   *");
    puts("***************************************************");
    puts("");
    puts("Press Enter to continue or Ctrl + C to abort.");
    getchar();
}

static void Help() {
    puts("***************************************************");
    puts("*       Navicat Patcher by @DoubleLabyrinth       *");
    puts("*                  Version: 3.0                   *");
    puts("***************************************************");
    puts("");
    puts("Usage:");
    puts("    navicat-patcher.exe <Navicat installation path> [RSA-2048 PEM file]");
    puts("");
}

static void LoadKey(RSACipher* pCipher, const char* FileName,
                    PatchSolution* pSolution0,
                    PatchSolution* pSolution1,
                    PatchSolution* pSolution2) {
    if (FileName) {
        pCipher->ImportKeyFromFile<RSAKeyType::PrivateKey, RSAKeyFormat::PEM>(FileName);

        if ((pSolution0 && !pSolution0->CheckKey(pCipher)) ||
            (pSolution1 && !pSolution1->CheckKey(pCipher)) ||
            (pSolution2 && !pSolution2->CheckKey(pCipher)))
            throw Exception(__FILE__, __LINE__,
                            "The RSA private key you provide cannot be used.");
    } else {
        puts("MESSAGE: Generating new RSA private key, it may take a long time.");

        do {
            pCipher->GenerateKey(2048);
        } while ((pSolution0 && !pSolution0->CheckKey(pCipher)) ||
                 (pSolution1 && !pSolution1->CheckKey(pCipher)) ||
                 (pSolution2 && !pSolution2->CheckKey(pCipher)));   // re-generate RSA key if CheckKey return false

        pCipher->ExportKeyToFile<RSAKeyType::PrivateKey, RSAKeyFormat::NotSpecified>("RegPrivateKey.pem");

        puts("MESSAGE: New RSA private key has been saved to RegPrivateKey.pem.");
    }

    std::string PublicKeyPEM =
        pCipher->ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

    puts("");
    puts("Your RSA public key:");
    puts(PublicKeyPEM.c_str());
}

static void ExceptionReport(const Exception& e) noexcept {
    printf("ERROR: FileName %s - Line %zu\n", e.SourceFile(), e.SourceLine());
    if (e.HasErrorCode()) {
        const char* aa = e.ErrorString();
        printf("ErrorCode = 0x%08lx\n", e.ErrorCode());
        printf("ErrorString: %s\n", e.ErrorString());
    } else {
        printf("%s\n", e.CustomMessage());
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2 && argc != 3) {
        Help();
        return 0;
    }

    Welcome();

    ResourceObject<FileHandleTraits> MainAppFile;
    ResourceObject<MapViewTraits> MainAppMapView;
    ResourceObject<CppObjectTraits<RSACipher>> pCipher;
    ResourceObject<CppObjectTraits<PatchSolution>> pSolution0;
    ResourceObject<CppObjectTraits<PatchSolution>> pSolution1;
    ResourceObject<CppObjectTraits<PatchSolution>> pSolution2;

    try {
        MainAppFile.TakeOver(open(argv[1], O_RDWR));
        if (!MainAppFile.IsValid())
            throw SystemError(__FILE__, __LINE__, errno,
                              "open fails.");

        struct stat stat_buf = {};
        if (fstat(MainAppFile, &stat_buf) != 0)
            throw SystemError(__FILE__, __LINE__, errno,
                              "fstat fails.");

        MainAppMapView.TakeOver({
            mmap(nullptr, static_cast<size_t>(stat_buf.st_size), PROT_READ | PROT_WRITE, MAP_SHARED, MainAppFile, 0),
            static_cast<size_t>(stat_buf.st_size)
        });
        if (!MainAppMapView.IsValid())
            throw SystemError(__FILE__, __LINE__, errno,
                              "mmap fails.");

        pCipher.TakeOver(new RSACipher());
        pSolution0.TakeOver(new PatchSolution0());
        pSolution1.TakeOver(new PatchSolution1());
        pSolution2.TakeOver(new PatchSolution2());

        pSolution0->SetFile(MainAppMapView);
        pSolution1->SetFile(MainAppMapView);
        pSolution2->SetFile(MainAppMapView);

        if (!pSolution0->FindPatchOffset())
            pSolution0.Release();
        if (!pSolution1->FindPatchOffset())
            pSolution1.Release();
        if (!pSolution2->FindPatchOffset())
            pSolution2.Release();

        if (!pSolution0.IsValid() && !pSolution1.IsValid() && !pSolution2.IsValid()) {
            puts("MESSAGE: Patch abort. None of PatchSolutions applied.");
            return 0;
        }

        LoadKey(pCipher, argc == 3 ? argv[2] : nullptr, pSolution0, pSolution1, pSolution2);

        if (pSolution0.IsValid())
            pSolution0->MakePatch(pCipher);
        if (pSolution1.IsValid())
            pSolution1->MakePatch(pCipher);
        if (pSolution2.IsValid())
            pSolution2->MakePatch(pCipher);

        if (pSolution0.IsValid())
            puts("MESSAGE: PatchSolution0 has been applied.");
        if (pSolution1.IsValid())
            puts("MESSAGE: PatchSolution1 has been applied.");
        if (pSolution2.IsValid())
            puts("MESSAGE: PatchSolution2 has been applied.");

        puts("MESSAGE: Patch has been done successfully. Have fun and enjoy~");

        return 0;
    } catch (Exception& e) {
        ExceptionReport(e);
        return static_cast<int>(e.ErrorCode());
    }
}

