#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <Exception.hpp>
#include <ExceptionUser.hpp>
#include <RSACipher.hpp>
#include "SerialNumberGenerator.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-keygen\\_tmain.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {
    using fnCollectInformation = SerialNumberGenerator();
    using fnGenerateLicense = void(const RSACipher& Cipher, const SerialNumberGenerator& Generator);

    SerialNumberGenerator CollectInformationNormal();
    SerialNumberGenerator CollectInformationAdvanced();
    void GenerateLicenseText(const RSACipher& Cipher, const SerialNumberGenerator& Generator);
    void GenerateLicenseBinary(const RSACipher& Cipher, const SerialNumberGenerator& Generator);
}

static void Welcome() {
    _putts(TEXT("***************************************************"));
    _putts(TEXT("*       Navicat Keygen by @DoubleLabyrinth        *"));
    _putts(TEXT("*                   Version: 4.0                  *"));
    _putts(TEXT("***************************************************"));
    _putts(TEXT(""));
}

static void Help() {
    _putts(TEXT("Usage:"));
    _putts(TEXT("    navicat-keygen.exe <-bin|-text> [-adv] <RSA-2048 Private Key File>"));
    _putts(TEXT(""));
    _putts(TEXT("    <-bin|-text>       Specify \"-bin\" to generate \"license_file\" used by Navicat 11."));
    _putts(TEXT("                       Specify \"-text\" to generate base64-encoded activation code."));
    _putts(TEXT("                       This parameter must be specified."));
    _putts(TEXT(""));
    _putts(TEXT("    [-adv]             Enable advance mode."));
    _putts(TEXT("                       This parameter is optional."));
    _putts(TEXT(""));
    _putts(TEXT("    <RSA-2048 Private Key File>    A path to an RSA-2048 private key file."));
    _putts(TEXT("                                   This parameter must be specified."));
    _putts(TEXT(""));
    _putts(TEXT("Example:"));
    _putts(TEXT("    navicat-keygen.exe -text .\\RegPrivateKey.pem"));
}

int _tmain(int argc, PTSTR argv[]) {
    Welcome();

    if (argc == 3 || argc == 4) {
        nkg::fnCollectInformation* lpfnCollectInformation = nullptr;
        nkg::fnGenerateLicense* lpfnGenerateLicense = nullptr;

        if (_tcsicmp(argv[1], TEXT("-bin")) == 0) {
            lpfnGenerateLicense = nkg::GenerateLicenseBinary;
        } else if (_tcsicmp(argv[1], TEXT("-text")) == 0) {
            lpfnGenerateLicense = nkg::GenerateLicenseText;
        } else {
            Help();
            return -1;
        }

        if (argc == 4) {
            if (_tcsicmp(argv[2], TEXT("-adv")) == 0) {
                lpfnCollectInformation = nkg::CollectInformationAdvanced;
            } else {
                Help();
                return -1;
            }
        } else {
            lpfnCollectInformation = nkg::CollectInformationNormal;
        }

        try {
            nkg::RSACipher Cipher;

            Cipher.ImportKeyFromFile<nkg::RSAKeyType::PrivateKey, nkg::RSAKeyFormat::PEM>(argv[argc - 1]);
            if (Cipher.Bits() != 2048) {
                throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("RSA key length mismatches."))
                    .AddHint(TEXT("You must provide an RSA key whose modulus length is 2048 bits."));
            }

            auto Generator = lpfnCollectInformation();

            Generator.Generate();
            Generator.ShowInConsole();

            lpfnGenerateLicense(Cipher, Generator);

            return 0;
        } catch (nkg::UserAbortionError&) {
            return -1;
        } catch (nkg::Exception& e) {
            _tprintf_s(TEXT("[-] %s:%zu ->\n"), e.File(), e.Line());
            _tprintf_s(TEXT("    %s\n"), e.Message());

            if (e.HasErrorCode()) {
                _tprintf_s(TEXT("    %s (0x%zx)\n"), e.ErrorString(), e.ErrorCode());
            }

            for (auto& Hint : e.Hints()) {
                _tprintf_s(TEXT("    Hints: %s\n"), Hint.c_str());
            }

            return -1;
        } catch (std::exception& e) {
            _tprintf_s(TEXT("[-] %hs\n"), e.what());
            return -1;
        }
    } else {
        Help();
        return -1;
    }
}
