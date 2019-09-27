#include <tchar.h>
#include <stdio.h>
#include <windows.h>

#include <Exception.hpp>
#include <ExceptionWin32.hpp>
#include <ResourceOwned.hpp>
#include <ResourceTraitsWin32.hpp>
#include "ImageInterpreter.hpp"
#include "PatchSolutions.hpp"
#include "Misc.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\_tmain.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

static void Welcome() {
    _putts(TEXT("***************************************************"));
    _putts(TEXT("*       Navicat Patcher by @DoubleLabyrinth       *"));
    _putts(TEXT("*                  Version: 4.1                   *"));
    _putts(TEXT("***************************************************"));
    _putts(TEXT(""));
    _putts(TEXT("Press Enter to continue or Ctrl + C to abort."));
    auto c = _gettchar();
    while (c != TEXT('\n') && _gettchar() != TEXT('\n')) {}
}

static void Help() {
    _putts(TEXT("***************************************************"));
    _putts(TEXT("*       Navicat Patcher by @DoubleLabyrinth       *"));
    _putts(TEXT("*                  Version: 4.1                   *"));
    _putts(TEXT("***************************************************"));
    _putts(TEXT(""));
    _putts(TEXT("Usage:"));
    _putts(TEXT("    navicat-patcher.exe [-dry-run] <Navicat Installation Path> [RSA-2048 PEM File Path]"));
    _putts(TEXT(""));
    _putts(TEXT("    [-dry-run]                   Run patcher without applying any patches."));
    _putts(TEXT("                                 This parameter is optional."));
    _putts(TEXT(""));
    _putts(TEXT("    <Navicat Installation Path>  The folder path where Navicat is installed."));
    _putts(TEXT("                                 This parameter must be specified."));
    _putts(TEXT(""));
    _putts(TEXT("    [RSA-2048 PEM File Path]     The path to an RSA-2048 private key file."));
    _putts(TEXT("                                 This parameter is optional."));
    _putts(TEXT("                                 If not specified, an RSA-2048 private key file"));
    _putts(TEXT("                                 named \"RegPrivateKey.pem\" will be generated."));
    _putts(TEXT(""));
    _putts(TEXT("Example:"));
    _putts(TEXT("    navicat-patcher.exe \"C:\\Program Files\\PremiumSoft\\Navicat Premium 12\""));
}

static bool ParseCommandLine(int argc, PTSTR argv[], bool& bDryRun, std::xstring& NavInstallPath, std::xstring& RsaPrivateKeyPath) {
    if (argc == 2) {
        bDryRun = false;
        NavInstallPath = argv[1];
        RsaPrivateKeyPath.clear();
        return true;
    } else if (argc == 3) {
        if (_tcsicmp(argv[1], TEXT("-dry-run")) == 0) {
            bDryRun = true;
            NavInstallPath = argv[2];
            RsaPrivateKeyPath.clear();
            return true;
        } else {
            bDryRun = false;
            NavInstallPath = argv[1];
            RsaPrivateKeyPath = argv[2];
            return true;
        }
    } else if (argc == 4) {
        if (_tcsicmp(argv[1], TEXT("-dry-run")) == 0) {
            bDryRun = true;
            NavInstallPath = argv[2];
            RsaPrivateKeyPath = argv[3];
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

static void SelectPatchSolutions(
    ResourceOwned<CppObjectTraits<nkg::PatchSolution>>& lpSolution0, 
    ResourceOwned<CppObjectTraits<nkg::PatchSolution>>& lpSolution1, 
    ResourceOwned<CppObjectTraits<nkg::PatchSolution>>& lpSolution2, 
    ResourceOwned<CppObjectTraits<nkg::PatchSolution>>& lpSolution3) 
{
    // if RSA public is detected in libcc.dll, don't patch main application to keep digital signature valid.
    if ((lpSolution1.IsValid() || lpSolution2.IsValid() || lpSolution3.IsValid()) && lpSolution0.IsValid()) {
        LOG_HINT(0, "PatchSolution0 is suppressed in order to keep digital signature valid.");
        lpSolution0.Release();
    }
}

static void NavicatBackupDetect(const std::xstring& FilePath) {
    if (std::xstring BackupPath = FilePath + TEXT(".backup"); nkg::IsValidFilePath(BackupPath.c_str()) == true) {
        while (true) {
            LOG_SELECT(0, "Previous backup %s detected. Delete? (y/n)", BackupPath.c_str());

            auto select = _gettchar(); 
            while (select != TEXT('\n') && _gettchar() != TEXT('\n')) {}
            if (select == TEXT('Y') || select == TEXT('y')) {
                if (!DeleteFile(BackupPath.c_str())) {
                    throw nkg::Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("Failed to delete backup file."));
                } else {
                    break;
                }
            } else if (select == TEXT('N') || select == TEXT('n')) {
                throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Backup file still existed. Patch abort!"));
            } else {
                continue;
            }
        }

        _putts(TEXT(""));
    }
}

static void NavicatBackupMake(const std::xstring& FilePath) {
    std::xstring BackupPath = FilePath + TEXT(".backup");
    if (CopyFile(FilePath.c_str(), BackupPath.c_str(), TRUE) == FALSE) {
        throw nkg::Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("CopyFile failed."));
    }
}

static void LoadKey(
    nkg::RSACipher& Cipher, const std::xstring& KeyFilePath,
    nkg::PatchSolution* pSolution0,
    nkg::PatchSolution* pSolution1,
    nkg::PatchSolution* pSolution2,
    nkg::PatchSolution* pSolution3,
    nkg::PatchSolution* pSolution4) 
{
    if (KeyFilePath.empty() == false) {
        LOG_HINT(0, "Import RSA-2048 key from %s", KeyFilePath.c_str());

        Cipher.ImportKeyFromFile<nkg::RSAKeyType::PrivateKey, nkg::RSAKeyFormat::PEM>(KeyFilePath);

        if (pSolution0 && !pSolution0->CheckKey(Cipher) ||
            pSolution1 && !pSolution1->CheckKey(Cipher) ||
            pSolution2 && !pSolution2->CheckKey(Cipher) ||
            pSolution3 && !pSolution3->CheckKey(Cipher) ||
            pSolution4 && !pSolution4->CheckKey(Cipher))
        {
            throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("The RSA private key you provide cannot be used."));
        }
    } else {
        LOG_HINT(0, "Generating new RSA private key, it may take a long time...");

        do {
            Cipher.GenerateKey(2048);
        } while (pSolution0 && !pSolution0->CheckKey(Cipher) ||
                 pSolution1 && !pSolution1->CheckKey(Cipher) ||
                 pSolution2 && !pSolution2->CheckKey(Cipher) ||
                 pSolution3 && !pSolution3->CheckKey(Cipher) ||
                 pSolution4 && !pSolution4->CheckKey(Cipher));   // re-generate RSA key if one of 'CheckKey's return false
    }

    LOG_HINT(0, "Your RSA public key:\n%hs", Cipher.ExportKeyString<nkg::RSAKeyType::PublicKey, nkg::RSAKeyFormat::PEM>().c_str());
}

int _tmain(int argc, PTSTR argv[]) {
    bool bDryRun;
    std::xstring NavInstallPath;
    std::xstring RsaPrivateKeyPath;

    if (ParseCommandLine(argc, argv, bDryRun, NavInstallPath, RsaPrivateKeyPath) == false) {
        Help();
        return -1;
    } else {
        Welcome();

        try {
            if (nkg::IsValidDirectoryPath(NavInstallPath.c_str()) == false) {
                throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Navicat installation path doesn't point to a directory."))
                    .AddHint(TEXT("Are you sure the path you specified is correct?"))
                    .AddHint(std::xstring::format(TEXT("The path you specified: %s"), NavInstallPath.c_str()));
            }

            if (RsaPrivateKeyPath.empty() == false && nkg::IsValidFilePath(RsaPrivateKeyPath.c_str()) == false) {
                throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("RSA key file path doesn't point to a file."))
                    .AddHint(TEXT("Are you sure the path you specified is correct?"))
                    .AddHint(std::xstring::format(TEXT("The path you specified: %s"), RsaPrivateKeyPath.c_str()));
            }

            while (NavInstallPath.back() == TEXT('\\') || NavInstallPath.back() == TEXT('/')) {
                NavInstallPath.pop_back();
            }

            NavInstallPath.push_back(nkg::IsWineEnvironment() ? TEXT('/') : TEXT('\\'));

            nkg::RSACipher Cipher;
            
            std::xstring MainExePath;
            ResourceOwned hMainExe(FileHandleTraits{});
            ResourceOwned hMainExeMapping(GenericHandleTraits{});
            ResourceOwned lpMainExeMapping(MapViewHandleTraits{});
            ResourceOwned lpMainExeInterpreter(CppObjectTraits<nkg::ImageInterpreter>{});

            std::xstring LibccDllPath;
            ResourceOwned hLibccDll(FileHandleTraits{});
            ResourceOwned hLibccDllMapping(GenericHandleTraits{});
            ResourceOwned lpLibccDllMapping(MapViewHandleTraits{});
            ResourceOwned lpLibccDllInterpreter(CppObjectTraits<nkg::ImageInterpreter>{});

            ResourceOwned lpSolution0(CppObjectTraits<nkg::PatchSolution>{});
            ResourceOwned lpSolution1(CppObjectTraits<nkg::PatchSolution>{});
            ResourceOwned lpSolution2(CppObjectTraits<nkg::PatchSolution>{});
            ResourceOwned lpSolution3(CppObjectTraits<nkg::PatchSolution>{});
            ResourceOwned lpSolution4(CppObjectTraits<nkg::PatchSolution>{});

            //
            // Open main application
            //
            do {
                MainExePath = NavInstallPath + TEXT("Navicat.exe");
                hMainExe.TakeOver(
                    CreateFile(MainExePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)
                );
                if (hMainExe.IsValid()) {
                    LOG_SUCCESS(0, "Try to open Navicat.exe ... Ok!");
                    break;
                } else if (GetLastError() == ERROR_FILE_NOT_FOUND) {
                    LOG_FAILURE(0, "Try to open Navicat.exe ... Not found!");
                } else {
                    throw nkg::Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("Failed to open Navicat.exe"));
                }

                MainExePath = NavInstallPath + TEXT("Modeler.exe");
                hMainExe.TakeOver(
                    CreateFile(MainExePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)
                );
                if (hMainExe.IsValid()) {
                    LOG_SUCCESS(0, "Try to open Modeler.exe ... Ok!");
                    break;
                } else if (GetLastError() == ERROR_FILE_NOT_FOUND) {
                    LOG_FAILURE(0, "Try to open Modeler.exe ... Not found!");
                } else {
                    throw nkg::Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("Failed to open Modeler.exe"));
                }

                MainExePath = NavInstallPath + TEXT("Rviewer.exe");
                hMainExe.TakeOver(
                    CreateFile(MainExePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)
                );
                if (hMainExe.IsValid()) {
                    LOG_SUCCESS(0, "Try to open Rviewer.exe ... Ok!");
                    break;
                } else if (GetLastError() == ERROR_FILE_NOT_FOUND) {
                    LOG_FAILURE(0, "Try to open Rviewer.exe ... Not found!");
                } else {
                    throw nkg::Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("Failed to open Rviewer.exe"));
                }

                throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Main application is not found."))
                    .AddHint(TEXT("Are you sure you specified a valid Navicat installation path?"))
                    .AddHint(std::xstring::format(TEXT("The path you specified: %s"), NavInstallPath.c_str()));
            } while (false);

            //
            // Open libcc.dll, if have
            //
            do {
                LibccDllPath = NavInstallPath + TEXT("libcc.dll");
                hLibccDll.TakeOver(
                    CreateFile(LibccDllPath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)
                );
                if (hLibccDll.IsValid()) {
                    LOG_SUCCESS(0, "Try to open libcc.dll ... Ok!");
                    break;
                } else if (GetLastError() == ERROR_FILE_NOT_FOUND) {
                    LOG_FAILURE(0, "Try to open libcc.dll ... Not found!");
                } else {
                    throw nkg::Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("Failed to open libcc.dll"));
                }
            } while (false);

            _putts(TEXT(""));

            //
            // Map main application
            //
            hMainExeMapping.TakeOver(CreateFileMapping(hMainExe, NULL, PAGE_READWRITE, 0, 0, NULL));
            if (hMainExeMapping.IsValid() == false) {
                throw nkg::Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("CreateFileMapping failed."));
            }

            lpMainExeMapping.TakeOver(MapViewOfFile(hMainExeMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0));
            if (hMainExeMapping.IsValid() == false) {
                throw nkg::Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("MapViewOfFile failed."));
            }

            lpMainExeInterpreter.TakeOver(
                new nkg::ImageInterpreter(nkg::ImageInterpreter::ParseImage(lpMainExeMapping))
            );

            lpSolution0.TakeOver(new nkg::PatchSolution0(lpMainExeInterpreter));

            //
            // Map libcc.dll, if have
            //
            if (hLibccDll.IsValid()) {
                hLibccDllMapping.TakeOver(CreateFileMapping(hLibccDll, NULL, PAGE_READWRITE, 0, 0, NULL));
                if (hMainExeMapping.IsValid() == false) {
                    throw nkg::Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("CreateFileMapping failed."));
                }

                lpLibccDllMapping.TakeOver(MapViewOfFile(hLibccDllMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0));
                if (hMainExeMapping.IsValid() == false) {
                    throw nkg::Win32Error(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), GetLastError(), TEXT("MapViewOfFile failed."));
                }

                lpLibccDllInterpreter.TakeOver(
                    new nkg::ImageInterpreter(nkg::ImageInterpreter::ParseImage(lpLibccDllMapping))
                );

                lpSolution1.TakeOver(new nkg::PatchSolution1(lpLibccDllInterpreter));
                lpSolution2.TakeOver(new nkg::PatchSolution2(lpLibccDllInterpreter));
                lpSolution3.TakeOver(new nkg::PatchSolution3(lpLibccDllInterpreter));
                lpSolution4.TakeOver(new nkg::PatchSolution4(lpLibccDllInterpreter));
            }

            //
            // Finding patch offsets
            //

            if (lpSolution0->FindPatchOffset() == false) {
                lpSolution0.Release();
            }

            if (lpSolution1.IsValid() && lpSolution1->FindPatchOffset() == false) {
                lpSolution1.Release();
            }

            if (lpSolution2.IsValid() && lpSolution2->FindPatchOffset() == false) {
                lpSolution2.Release();
            }

            if (lpSolution3.IsValid() && lpSolution3->FindPatchOffset() == false) {
                lpSolution3.Release();
            }

            if (lpSolution4.IsValid() && lpSolution4->FindPatchOffset() == false) {
                lpSolution4.Release();
            }

            _putts(TEXT(""));

            //
            //  decide which solutions will be applied
            //
            SelectPatchSolutions(lpSolution0, lpSolution1, lpSolution2, lpSolution3);

            if (lpSolution0.IsValid() == false && lpSolution1.IsValid() == false && lpSolution2.IsValid() == false && lpSolution3.IsValid() == false && lpSolution4.IsValid() == false) {
                throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("No patch applied. Patch abort!"))
                    .AddHint(TEXT("Are you sure your Navicat has not been patched/modified before?"));
            }

            _putts(TEXT(""));

            //
            // detecting backups
            //
            if (lpSolution0.IsValid()) {
                NavicatBackupDetect(MainExePath);
            }

            if (lpSolution1.IsValid() || lpSolution2.IsValid() || lpSolution3.IsValid() || lpSolution4.IsValid()) {
                NavicatBackupDetect(LibccDllPath);
            }

            //
            // Loading key
            //
            LoadKey(Cipher, RsaPrivateKeyPath, lpSolution0, lpSolution1, lpSolution2, lpSolution3, lpSolution4);

            if (bDryRun == false) {
                //
                // Saving private key if not given
                //
                if (RsaPrivateKeyPath.empty()) {
                    Cipher.ExportKeyToFile<nkg::RSAKeyType::PrivateKey, nkg::RSAKeyFormat::PEM>(std::xstring{ std::xstring_extension{}, "RegPrivateKey.pem" });
                }

                //
                // Making backups
                //
                if (lpSolution0.IsValid()) {
                    NavicatBackupMake(MainExePath);
                }

                if (lpSolution1.IsValid() || lpSolution2.IsValid() || lpSolution3.IsValid() || lpSolution4.IsValid()) {
                    NavicatBackupMake(LibccDllPath);
                }

                //
                // Making patch. No way to go back here :-)
                //
                if (lpSolution0.IsValid()) {
                    lpSolution0->MakePatch(Cipher);
                }

                if (lpSolution1.IsValid()) {
                    lpSolution1->MakePatch(Cipher);
                }

                if (lpSolution2.IsValid()) {
                    lpSolution2->MakePatch(Cipher);
                }

                if (lpSolution3.IsValid()) {
                    lpSolution3->MakePatch(Cipher);
                }

                if (lpSolution4.IsValid()) {
                    lpSolution4->MakePatch(Cipher);
                }
                
                if (RsaPrivateKeyPath.empty()) {
                    LOG_HINT(
                        0,
                        "New RSA-2048 private key has been saved to\n%s%cRegPrivateKey.pem",
                        nkg::GetCurrentWorkingDirectory().c_str(),
                        nkg::IsWineEnvironment() ? TEXT('/') : TEXT('\\')
                    );

                    _putts(TEXT(""));
                }
                
                _putts(TEXT("*******************************************************"));
                _putts(TEXT("*           PATCH HAS BEEN DONE SUCCESSFULLY!         *"));
                _putts(TEXT("*                  HAVE FUN AND ENJOY~                *"));
                _putts(TEXT("*******************************************************"));
            } else {
                _putts(TEXT("*******************************************************"));
                _putts(TEXT("*               DRY-RUN MODE ENABLE!                  *"));
                _putts(TEXT("*             NO PATCH WILL BE APPLIED!               *"));
                _putts(TEXT("*******************************************************"));
            }

            return 0;
        } catch (nkg::Exception& e) {
            LOG_FAILURE(0, "%s:%zu ->", e.File(), e.Line());
            LOG_FAILURE(4, "%s", e.Message());
            if (e.HasErrorCode()) {
                LOG_HINT(4, "%s (0x%zx)", e.ErrorString(), e.ErrorCode());
            }
            
            for (auto& Hint : e.Hints()) {
                LOG_HINT(4, "Hint: %s", Hint.c_str());
            }
            return -1;
        }
    }
}

