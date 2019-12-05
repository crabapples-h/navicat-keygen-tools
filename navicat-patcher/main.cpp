#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include "Exception.hpp"
#include "ExceptionSystem.hpp"
#include "ResourceWrapper.hpp"
#include "ResourceTraitsUnix.hpp"
#include "Elf64Interpreter.hpp"
#include "PatchSolutions.hpp"
#include "Misc.hpp"

static void Welcome(bool bWait) {
    puts("**********************************************************");
    puts("*       Navicat Patcher (Linux) by @DoubleLabyrinth      *");
    puts("*                  Version: 1.0                          *");
    puts("**********************************************************");
    puts("");
    if (bWait) {
        puts("Press ENTER to continue or Ctrl + C to abort.");
        getchar();
    }
}

static void Help() {
    puts("Usage:");
    puts("    navicat-patcher [--dry-run] <Navicat installation path> [RSA-2048 Private Key File]");
    puts("");
    puts("    [--dry-run]                   Run patcher without applying any patches.");
    puts("                                  This parameter is optional.");
    puts("");
    puts("    <Navicat installation path>   Path to directory where Navicat is installed.");
    puts("                                  This parameter must be specified.");
    puts("");
    puts("    [RSA-2048 Private Key File]   Path to a PEM-format RSA-2048 private key file.");
    puts("                                  This parameter is optional.");
    puts("");
}

static bool ParseCommandLine(int argc, char* argv[], bool& bDryrun, std::string& szInstallPath, std::string& szKeyFilePath) {
    if (argc == 2) {
        bDryrun = false;
        szInstallPath = argv[1];
        szKeyFilePath.clear();
        return true;
    } else if (argc == 3) {
        if (strcasecmp(argv[1], "--dry-run") == 0) {
            bDryrun = true;
            szInstallPath = argv[2];
            szKeyFilePath.clear();
            return true;
        } else {
            bDryrun = false;
            szInstallPath = argv[1];
            szKeyFilePath = argv[2];
            return true;
        }
    } else if (argc == 4) {
        if (strcasecmp(argv[1], "--dry-run") == 0) {
            bDryrun = true;
            szInstallPath = argv[2];
            szKeyFilePath = argv[3];
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

static void SelectPatchSolutions(ARL::ResourceWrapper<ARL::ResourceTraits::CppObject<nkg::PatchSolution>>& lpSolution0) {
    // pass
}

static void NavicatBackupDetect(std::string_view szFilePath) {
    std::string szBackupPath(szFilePath);
    szBackupPath += ".bak";
    if (nkg::Misc::FsIsExist(szBackupPath) == true) {
        while (true) {
            printf("[?] Previous backup %s is detected. Delete? (y/n)", szBackupPath.c_str());

            auto select = getchar(); 
            while (select != '\n' && getchar() != '\n') {}

            if (select == 'Y' || select == 'y') {
                nkg::Misc::FsDeleteFile(szBackupPath);
                break;
            } else if (select == 'N' || select == 'n') {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "Backup file still existed. Patch abort!");
            } else {
                continue;
            }
        }

        printf("\n");
    }
}

static void NavicatBackupMake(std::string_view szFilePath) {
    std::string szBackupPath(szFilePath);
    szBackupPath += ".bak";
    nkg::Misc::FsCopyFile(szFilePath, szBackupPath);
}

static void LoadKey(nkg::RSACipher& Cipher, 
                    std::string_view szKeyFileName,
                    nkg::PatchSolution* lpSolution0) {
    if (szKeyFileName.empty() == false) {
        printf("[*] Import RSA-2048 key from %s\n", szKeyFileName.data());

        Cipher.ImportKeyFromFile<nkg::RSAKeyType::PrivateKey, nkg::RSAKeyFormat::PEM>(szKeyFileName);

        if (lpSolution0 && lpSolution0->CheckKey(Cipher) == false) {
            throw ARL::Exception(__BASE_FILE__, __LINE__, "The RSA private key you provide cannot be used.");
        }
    } else {
        printf("[*] Generating new RSA private key, it may take a long time...\n");

        do {
            Cipher.GenerateKey(2048);
        } while (lpSolution0 && lpSolution0->CheckKey(Cipher) == false);   // re-generate RSA key if CheckKey return false
    }

    printf("[*] Your RSA private key:\n");
    printf("    %s\n", 
        [&Cipher]() -> std::string {
            auto szPrivateKey = Cipher.ExportKeyString<nkg::RSAKeyType::PrivateKey, nkg::RSAKeyFormat::PEM>();
            for (size_t pos = 0; (pos = szPrivateKey.find('\n', pos)) != std::string::npos; pos += strlen("\n    ")) {
                szPrivateKey.replace(pos, 1, "\n    ");
            }
            return szPrivateKey;
        }().c_str()
    );

    printf("[*] Your RSA public key:\n");
    printf("    %s\n", 
        [&Cipher]() -> std::string {
            auto szPublicKey = Cipher.ExportKeyString<nkg::RSAKeyType::PublicKey, nkg::RSAKeyFormat::PEM>();
            for (size_t pos = 0; (pos = szPublicKey.find('\n', pos)) != std::string::npos; pos += strlen("\n    ")) {
                szPublicKey.replace(pos, 1, "\n    ");
            }
            return szPublicKey;
        }().c_str()
    );
    //printf("%s\n", Cipher.ExportKeyString<nkg::RSAKeyType::PublicKey, nkg::RSAKeyFormat::PEM>().c_str());

    printf("\n");
}

int main(int argc, char* argv[]) {
    bool bDryrun;
    std::string szInstallPath;
    std::string szKeyFilePath;

    if (ParseCommandLine(argc, argv, bDryrun, szInstallPath, szKeyFilePath) == false) {
        Welcome(false);
        Help();
        return -1;
    } else {
        Welcome(true);

        try {
            if (nkg::Misc::FsIsDirectory(szInstallPath) == false) {
                 throw ARL::Exception(__BASE_FILE__, __LINE__, "Navicat installation path doesn't point to a directory.")
                    .PushHint("Are you sure the path you specified is correct?")
                    .PushFormatHint("The path you specified: %s", szInstallPath.c_str());
            }

            if (szKeyFilePath.empty() == false && nkg::Misc::FsIsFile(szKeyFilePath) == false) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "RSA key file path doesn't point to a file.")
                    .PushHint("Are you sure the path you specified is correct?")
                    .PushFormatHint("The path you specified: %s", szKeyFilePath.c_str());
            }

            while (szInstallPath.back() == '/') {
                szInstallPath.pop_back();
            }

            nkg::RSACipher Cipher;
            ARL::ResourceWrapper<ARL::ResourceTraits::CppObject<nkg::PatchSolution>> lpSolution0;

            std::string             libcc_path;
            ARL::ResourceWrapper    libcc_fd{ ARL::ResourceTraits::FileDescriptor{} };
            ARL::ResourceWrapper    libcc_stat{ ARL::ResourceTraits::CppObject<struct stat>{} };
            ARL::ResourceWrapperEx  libcc_mmap{ ARL::ResourceTraits::MapView{}, [&libcc_stat](void* p) { 
                if (munmap(p, libcc_stat->st_size) < 0) {
                    throw ARL::SystemError(__BASE_FILE__, __LINE__, errno, "munmap failed.");
                } 
            } };
            ARL::ResourceWrapper    libcc_interpreter{ ARL::ResourceTraits::CppObject<nkg::Elf64Interpreter>{} };

            //
            // try open libcc.so
            //
            libcc_path = szInstallPath + "/usr/lib/libcc.so";
            libcc_fd.TakeOver(open(libcc_path.c_str(), O_RDWR));
            if (libcc_fd.IsValid()) {
                printf("[+] Try to open libcc.so ... Ok!\n");
            } else {
                if (errno == ENOENT) {
                    printf("[-] Try to open libcc.so ... Not found!\n");
                } else {
                    throw ARL::SystemError(__BASE_FILE__, __LINE__, errno, "open failed.");
                }
            }

            puts("");

            //
            // try map libcc.so
            //

            if (libcc_fd.IsValid()) {
                libcc_stat.TakeOver(new struct stat());
                if (fstat(libcc_fd, libcc_stat) != 0) {
                    throw ARL::SystemError(__BASE_FILE__, __LINE__, errno, "fstat failed.");
                }

                libcc_mmap.TakeOver(mmap(nullptr, libcc_stat->st_size, PROT_READ | PROT_WRITE, MAP_SHARED, libcc_fd, 0));
                if (libcc_mmap.IsValid() == false) {
                    throw ARL::SystemError(__BASE_FILE__, __LINE__, errno, "mmap failed.");
                }

                libcc_interpreter.TakeOver(
                    new nkg::Elf64Interpreter(nkg::Elf64Interpreter::Parse(libcc_mmap, libcc_stat->st_size))
                );

                lpSolution0.TakeOver(
                    new nkg::PatchSolution0(*libcc_interpreter.Get())
                );
            }

            //
            // Make sure that there is one patch solution at least existing.
            //
            if (lpSolution0.IsValid() == false) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "No patch applied. Patch abort!")
                    .PushHint("Are you sure your Navicat has not been patched/modified before?");
            }

            //
            // Finding patch offsets
            //

            if (lpSolution0.IsValid() && lpSolution0->FindPatchOffset() == false) {
                lpSolution0.Release();
            }

            printf("\n");

            //
            //  decide which solutions will be applied
            //
            SelectPatchSolutions(lpSolution0);

            //
            // Make sure that there is one patch solution at least existing.
            //
            if (lpSolution0.IsValid() == false) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "No patch applied. Patch abort!")
                    .PushHint("Are you sure your Navicat has not been patched/modified before?");
            }
            
            //
            // detecting backups
            //
            if (lpSolution0.IsValid()) {
                NavicatBackupDetect(libcc_path);
            }

            //
            //
            //
            LoadKey(Cipher, szKeyFilePath, lpSolution0);

            if (bDryrun == false) {
                //
                // Save private key if not given
                //
                if (szKeyFilePath.empty()) {
                    Cipher.ExportKeyToFile<nkg::RSAKeyType::PrivateKey, nkg::RSAKeyFormat::PEM>("RegPrivateKey.pem");
                }

                //
                // Making backups
                //
                if (lpSolution0.IsValid()) {
                    NavicatBackupMake(libcc_path);
                }

                //
                // Making patch. No way to go back here :-)
                //
                if (lpSolution0.IsValid()) {
                    lpSolution0->MakePatch(Cipher);
                }
                
                if (szKeyFilePath.empty()) {
                    printf("[*] New RSA-2048 private key has been saved to\n");
                    printf("    %s/RegPrivateKey.pem\n", nkg::Misc::FsCurrentWorkingDirectory().c_str());
                    printf("\n");
                }
                
                puts("*******************************************************");
                puts("*           PATCH HAS BEEN DONE SUCCESSFULLY!         *");
                puts("*                  HAVE FUN AND ENJOY~                *");
                puts("*******************************************************");
            } else {
                puts("*******************************************************");
                puts("*               DRY-RUN MODE ENABLE!                  *");
                puts("*             NO PATCH WILL BE APPLIED!               *");
                puts("*******************************************************");
            }

            return 0;
        } catch (ARL::Exception& e) {
            printf("[-] %s:%zu ->\n", e.ExceptionFile(), e.ExceptionLine());
            printf("    %s\n", e.ExceptionMessage());

            if (e.HasErrorCode()) {
                printf("    %s (0x%zx)\n", e.ErrorString(), e.ErrorCode());
            }

            for (const auto& Hint : e.Hints()) {
                printf("    Hints: %s\n", Hint.c_str());
            }

            return -1;
        }
    }
}

