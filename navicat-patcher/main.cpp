#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <plist/plist++.h>
#include <string>

#include "../common/ExceptionSystem.hpp"
#include "../common/ResourceOwned.hpp"
#include "ResourceTraitsUnix.hpp"
#include "PatchSolutions.hpp"

static void Welcome() {
    puts("***************************************************");
    puts("*       Navicat Patcher by @DoubleLabyrinth       *");
    puts("*                  Version: 4.0                   *");
    puts("***************************************************");
    puts("");
    puts("Press Enter to continue or Ctrl + C to abort.");
    getchar();
}

static void Help() {
    puts("***************************************************");
    puts("*       Navicat Patcher by @DoubleLabyrinth       *");
    puts("*                  Version: 4.0                   *");
    puts("***************************************************");
    puts("");
    puts("Usage:");
    puts("    navicat-patcher <Navicat installation path> [RSA-2048 Private Key File]");
    puts("");
    puts("        <Navicat installation path>    Path to `Navicat Premium.app`.");
    puts("                                       Example:");
    puts("                                           /Applications/Navicat\\ Premium.app/");
    puts("                                       This parameter must be specified.");
    puts("");
    puts("        [RSA-2048 Private Key File]    Path to a PEM-format RSA-2048 private key file.");
    puts("                                       This parameter is optional.");
    puts("");
}

static std::string GetNavicatVersion(const char* AppPath) {
    ResourceOwned hInfoPlist(FileHandleTraits{});
    ResourceOwned InfoPlist(CppObjectTraits<PList::Dictionary>{});

    hInfoPlist.TakeOver(open((std::string(AppPath) + "/Contents/Info.plist").c_str(), O_RDONLY));
    if (hInfoPlist.IsValid() == false) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::SystemError(__FILE__, __LINE__, errno, "Failed to open Contents/Info.plist.");
    }

    struct stat statInfoPlist = {};
    if (fstat(hInfoPlist, &statInfoPlist) != 0) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::SystemError(__FILE__, __LINE__, errno, "Failed to get file size of Contents/Info.plist.");
    }

    std::string contentInfoPlist(statInfoPlist.st_size, '\x00');
    if (read(hInfoPlist, contentInfoPlist.data(), contentInfoPlist.size()) != contentInfoPlist.size()) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::SystemError(__FILE__, __LINE__, errno, "Failed to read Contents/Info.plist.");
    }

    InfoPlist.TakeOver(dynamic_cast<PList::Dictionary*>(PList::Structure::FromXml(contentInfoPlist)));
    if (InfoPlist.IsValid() == false) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "Failed to parse Contents/Info.plist.");
    }

    auto kv = InfoPlist->Find("CFBundleShortVersionString");
    if (kv == InfoPlist->End()) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "Cannot find CFBundleShortVersionString in Contents/Info.plist.");
    }

    if (kv->second->GetType() == PLIST_STRING) {
        return dynamic_cast<PList::String*>(kv->second)->GetValue();
    } else {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "Failed to get Navicat version.");
    }
}

static void LoadKey(RSACipher& RsaCipher, const char* RsaKeyFileName,
                    PatchSolution* lpSolution0,
                    PatchSolution* lpSolution1,
                    PatchSolution* lpSolution2) {
    if (RsaKeyFileName) {
        RsaCipher.ImportKeyFromFile<RSAKeyType::PrivateKey, RSAKeyFormat::PEM>(RsaKeyFileName);

        if ((lpSolution0 && !lpSolution0->CheckKey(RsaCipher)) ||
            (lpSolution1 && !lpSolution1->CheckKey(RsaCipher)) ||
            (lpSolution2 && !lpSolution2->CheckKey(RsaCipher)))
        {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::Exception(__FILE__, __LINE__, "The RSA private key you provide cannot be used.");
        }
    } else {
        puts("");
        puts("[*] Generating new RSA private key, it may take a long time...");

        do {
            RsaCipher.GenerateKey(2048);
        } while ((lpSolution0 && !lpSolution0->CheckKey(RsaCipher)) ||
                 (lpSolution1 && !lpSolution1->CheckKey(RsaCipher)) ||
                 (lpSolution2 && !lpSolution2->CheckKey(RsaCipher)));   // re-generate RSA key if CheckKey return false

        RsaCipher.ExportKeyToFile<RSAKeyType::PrivateKey, RSAKeyFormat::PEM>("RegPrivateKey.pem");

        puts("[+] New RSA private key has been saved to RegPrivateKey.pem.");
    }

    std::string PublicKeyPEM = RsaCipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();
    puts("");
    puts("[*] Your RSA public key:");
    puts(PublicKeyPEM.c_str());
}

int main(int argc, char* argv[]) {
    if (argc != 2 && argc != 3) {
        Help();
        return -1;
    } else {
        Welcome();

        try {
            RSACipher RsaCipher;
            ResourceOwned Solution0(CppObjectTraits<PatchSolution>{});
            ResourceOwned Solution1(CppObjectTraits<PatchSolution>{});
            ResourceOwned Solution2(CppObjectTraits<PatchSolution>{});

            ResourceOwned hMainApp(FileHandleTraits{}, open((std::string(argv[1]) + "/Contents/MacOS/Navicat Premium").c_str(), O_RDWR));
            if (hMainApp.IsValid() == false) {
                // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                throw nkg::SystemError(__FILE__, __LINE__, errno, "open failed.");
            }

            struct stat statMainApp = {};
            if (fstat(hMainApp, &statMainApp) != 0) {
                // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                throw nkg::SystemError(__FILE__, __LINE__, errno, "fstat failed.");
            }

            ResourceOwned lpMainApp(MapViewTraits{},
                mmap(nullptr, static_cast<size_t>(statMainApp.st_size), PROT_READ | PROT_WRITE, MAP_SHARED, hMainApp, 0),
                [&statMainApp](void* p) { munmap(p, statMainApp.st_size); }
            );
            if (lpMainApp.IsValid() == false) {
                // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                throw nkg::SystemError(__FILE__, __LINE__, errno, "mmap failed.");
            }

            int Ver0, Ver1, Ver2;
            if (sscanf(GetNavicatVersion(argv[1]).c_str(), "%d.%d.%d", &Ver0, &Ver1, &Ver2) != 3) { // NOLINT
                // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                throw nkg::SystemError(__FILE__, __LINE__, errno, "Failed to get version of Navicat.");
            }

            X64ImageInterpreter MainApp = X64ImageInterpreter::Parse(lpMainApp);

            printf("[*] Your Navicat version: %d.%d.%d\n", Ver0, Ver1, Ver2);
            printf("\n");

            Solution0.TakeOver(new PatchSolution0(MainApp));
            Solution1.TakeOver(new PatchSolution1(MainApp));
            Solution2.TakeOver(new PatchSolution2(MainApp));

            if (Solution0->FindPatchOffset() == false) {
                Solution0.Release();
            }
            if (Solution1->FindPatchOffset() == false) {
                Solution1.Release();
            }
            if (Solution2->FindPatchOffset() == false) {
                Solution2.Release();
            }

            //
            // Begin strategies by different Navicat versions
            //
            if (Ver0 < 12) {    // ver < 12.0.0
                // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                throw nkg::SystemError(__FILE__, __LINE__, errno, "Unsupported version of Navicat.");
            } else if (Ver0 == 12 && Ver1 == 0 && Ver2 < 24) {                      // ver < 12.0.24
                std::string path(argv[1]);
                while(path.back() == '/') {
                    path.pop_back();
                }

                printf("[*] Your Navicat version is < 12.0.24. So there would be nothing patched.\n");
                printf("    Just use `openssl` to generate `RegPrivateKey.pem` and `rpk` file:\n");
                printf("        openssl genrsa -out RegPrivateKey.pem 2048\n");
                printf("        openssl rsa -in RegPrivateKey.pem -pubout -out rpk\n");
                printf("    and replace `%s/Contents/Resources/rpk` with the `rpk` file you just generated.\n", path.c_str());
                printf("\n");

                return 0;
            } else if (Ver0 == 12 && (Ver1 == 0 || (Ver1 == 1 && Ver2 < 14))) {      // 12.0.24 <= ver && ver < 12.1.14
                // In this case, Solution0 must be applied
                if (Solution0.IsValid() == false) {
                    puts("[-] Patch abort. None of PatchSolutions will be applied.");
                    puts("    Are you sure your Navicat has not been patched before?");
                    return -1;
                }
            } else if (Ver0 == 12 && Ver1 == 1 && Ver2 == 14) {                    // ver == 12.1.14
                // In this case, Solution0 and Solution1 must be applied
                if ((Solution0.IsValid() && Solution1.IsValid()) == false) {
                    puts("[-] Patch abort. None of PatchSolutions will be applied.");
                    puts("    Are you sure your Navicat has not been patched before?");
                    return -1;
                }
            } else {                                                                // ver > 12.1.14
                // In this case, Solution0 and Solution2 must be applied
                if ((Solution0.IsValid() && Solution2.IsValid()) == false) {
                    puts("[-] Patch abort. None of PatchSolutions will be applied.");
                    puts("    Are you sure your Navicat has not been patched before?");
                    return -1;
                }
            }
            //
            // End strategies by different Navicat versions
            //

            LoadKey(RsaCipher, argc == 3 ? argv[2] : nullptr, Solution0, Solution1, Solution2);

            if (Solution0.IsValid()) {
                Solution0->MakePatch(RsaCipher);
            }
            if (Solution1.IsValid()) {
                Solution1->MakePatch(RsaCipher);
            }
            if (Solution2.IsValid()) {
                Solution2->MakePatch(RsaCipher);
            }

            if (Solution0.IsValid())
                puts("[+] PatchSolution0 has been applied.");
            if (Solution1.IsValid())
                puts("[+] PatchSolution1 has been applied.");
            if (Solution2.IsValid())
                puts("[+] PatchSolution2 has been applied.");

            puts("");
            puts("**************************************************************");
            puts("*   Patch has been done successfully. Have fun and enjoy~~   *");
            puts("*    DO NOT FORGET TO SIGN NAVICAT BY YOUR CERTIFICATE!!!    *");
            puts("**************************************************************");

            return 0;
        } catch (nkg::Exception& e) {
            printf("[-] %s:%zu -> \n", e.File(), e.Line());
            printf("    %s\n", e.Message());
            if (e.HasErrorCode()) {
                printf("    %s\n", e.ErrorString());
            }
            return -1;
        }
    }
}

