#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "Helper.hpp"
#include "FileMapper.hpp"
#include "RSACipher.hpp"
#include "Solutions.hpp"

#define SAFE_DELETE(x) { delete x; x = nullptr; }

void help() {
    puts("Usage:");
    puts("    ./navicat-patcher <navicat executable file> [RSA-2048 PrivateKey(PEM file)]");
    puts("");
}

bool LoadKey(RSACipher* cipher, const char* filename,
             Patcher::Solution* pSolution0,
             Patcher::Solution* pSolution1) {
    if (filename) {
        if (!cipher->ImportKeyFromFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::PEM>(filename)) {
            REPORT_ERROR("ERROR: cipher->ImportKeyFromFile failed.");
            return false;
        }

        if ((pSolution0 && !pSolution0->CheckKey(cipher)) ||
            (pSolution1 && !pSolution1->CheckKey(cipher))) {
            REPORT_ERROR("ERROR: The RSA private key you provided cannot be used.");
            return false;
        }
    } else {
        PRINT_MESSAGE("");
        PRINT_MESSAGE("MESSAGE: Generating new RSA private key, it may take a long time.");

        do {
            cipher->GenerateKey(2048);
        } while ((pSolution0 && !pSolution0->CheckKey(cipher)) ||
                 (pSolution1 && !pSolution1->CheckKey(cipher)));   // re-generate RSA key if one of CheckKey return false

        if (!cipher->ExportKeyToFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::NotSpecified>("RegPrivateKey.pem")) {
            REPORT_ERROR("ERROR: Failed to save RSA private key.");
            return false;
        }

        PRINT_MESSAGE("MESSAGE: New RSA private key has been saved to RegPrivateKey.pem.");
    }

    std::string PublicKeyString = cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
    if (PublicKeyString.empty()) {
        REPORT_ERROR("ERROR: cipher->ExportKeyString failed.");
        return false;
    }

    PRINT_MESSAGE("");
    PRINT_MESSAGE("Your RSA public key:");
    PRINT_MESSAGE(PublicKeyString.c_str());
    return true;
}

int main(int argc, char* argv[], char* envp[]) {
    int status = 0;
    FileMapper MainApp;
    off_t MainAppSize;
    Helper::ResourceGuard<RSACipher> cipher(nullptr);
    Helper::ResourceGuard<Patcher::Solution> pSolution0(nullptr);
    Helper::ResourceGuard<Patcher::Solution> pSolution1(nullptr);

    if (argc != 2 && argc != 3) {
        help();
        return status;
    }

    PRINT_MESSAGE("NOTICE:");
    printf("This patcher will modify the file: %s\n", argv[1]);
    PRINT_MESSAGE("Please make a backup by your own if you care. Otherwise just ignore this notice.");
    PRINT_MESSAGE("Press Enter to continue OR Ctrl+C to abort...");
    getchar();

    cipher.ptr = RSACipher::Create();
    if (cipher.ptr == nullptr) {
        REPORT_ERROR("ERROR: RSACipher::Create failed.");
        return status;
    }
    pSolution0.ptr = new Patcher::Solution0();
    pSolution1.ptr = new Patcher::Solution1();

    //
    //  Map file
    //
    if (!MainApp.OpenFile(argv[1])) {
        status = errno;
        REPORT_ERROR_WITH_CODE("Failed to open file.");
        return status;
    } else {
        PRINT_MESSAGE("MESSAGE: Open file successfully.");
    }

    if (!MainApp.GetFileSize(MainAppSize)) {
        status = errno;
        REPORT_ERROR_WITH_CODE("Failed to get file size.");
        return status;
    } else {
        printf("MESSAGE: Get file size successfully: %lld\n", MainAppSize);
    }

    if (!MainApp.Map(static_cast<size_t>(MainAppSize))) {
        status = errno;
        REPORT_ERROR_WITH_CODE("Failed to map file.");
        return status;
    } else {
        PRINT_MESSAGE("MESSAGE: Map file successfully.");
    }

    pSolution0.ptr->SetFile(&MainApp);
    pSolution1.ptr->SetFile(&MainApp);

    //
    //  Find patch offsets
    //
    if (!pSolution0.ptr->FindPatchOffset()) {
        PRINT_MESSAGE("MESSAGE: Solution0: Cannot find public key. Solution0 will be omitted.");
        pSolution0.ptr->SetFile(nullptr);
        SAFE_DELETE(pSolution0.ptr);
    }

    if (!pSolution1.ptr->FindPatchOffset()) {
        PRINT_MESSAGE("MESSAGE: Solution1: Cannot find public key. Solution1 will be omitted.");
        pSolution1.ptr->SetFile(nullptr);
        SAFE_DELETE(pSolution1.ptr);
    }

    //
    //  Load or generate RSA-2048 key
    //
    if (!LoadKey(cipher.ptr, argc == 3 ? argv[2] : nullptr, pSolution0.ptr, pSolution1.ptr))
        return status;

    //
    //  Making patch
    //
    if (pSolution0.ptr && !pSolution0.ptr->MakePatch(cipher.ptr))
        return status;
    if (pSolution1.ptr && !pSolution1.ptr->MakePatch(cipher.ptr))
        return status;

    //
    //  Report result
    //
    if (pSolution0.ptr)
        PRINT_MESSAGE("Solution0 has been done successfully.");
    if (pSolution1.ptr)
        PRINT_MESSAGE("Solution1 has been done successfully.");

    return status;
}
