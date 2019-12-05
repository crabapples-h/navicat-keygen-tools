#include <stdio.h>
#include <string.h>
#include "Exception.hpp"
#include "ExceptionGeneric.hpp"
#include "RSACipher.hpp"
#include "SerialNumberGenerator.hpp"

namespace nkg {
    using fnCollectInformation = SerialNumberGenerator();
    using fnGenerateLicense = void(const RSACipher& Cipher, const SerialNumberGenerator& Generator);

    SerialNumberGenerator CollectInformationNormal();
    SerialNumberGenerator CollectInformationAdvanced();
    void GenerateLicenseText(const RSACipher& Cipher, const SerialNumberGenerator& Generator);
    void GenerateLicenseBinary(const RSACipher& Cipher, const SerialNumberGenerator& Generator);
}

static void Welcome() {
    puts("**********************************************************");
    puts("*       Navicat Keygen (Linux) by @DoubleLabyrinth       *");
    puts("*                   Version: 1.0                         *");
    puts("**********************************************************");
    puts("");
}

static void Help() {
    puts("Usage:");
    puts("    navicat-keygen <--bin|--text> [--adv] <RSA-2048 Private Key File>");
    puts("");
    puts("    <--bin|--text>    Specify \"--bin\" to generate \"license_file\" used by Navicat 11.");
    puts("                      Specify \"--text\" to generate base64-encoded activation code.");
    puts("                      This parameter must be specified.");
    puts("");
    puts("    [--adv]                       Enable advance mode.");
    puts("                                  This parameter is optional.");
    puts("");
    puts("    <RSA-2048 Private Key File>   A path to an RSA-2048 private key file.");
    puts("                                  This parameter must be specified.");
    puts("");
    puts("Example:");
    puts("    ./navicat-keygen --text ./RegPrivateKey.pem");
}

int main(int argc, const char* argv[]) {
    Welcome();

    if (argc == 3 || argc == 4) {
        nkg::fnCollectInformation* lpfnCollectInformation = nullptr;
        nkg::fnGenerateLicense* lpfnGenerateLicense = nullptr;

        if (strcasecmp(argv[1], "--bin") == 0) {
            lpfnGenerateLicense = nkg::GenerateLicenseBinary;
        } else if (strcasecmp(argv[1], "--text") == 0) {
            lpfnGenerateLicense = nkg::GenerateLicenseText;
        } else {
            Help();
            return -1;
        }

        if (argc == 4) {
            if (strcasecmp(argv[2], "--adv") == 0) {
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
                throw ARL::Exception(__BASE_FILE__, __LINE__, "RSA key length mismatches.")
                    .PushHint("You must provide an RSA key whose modulus length is 2048 bits.");
            }

            auto Generator = lpfnCollectInformation();

            Generator.Generate();
            Generator.ShowInConsole();

            lpfnGenerateLicense(Cipher, Generator);

            return 0;
        } catch (ARL::EOFError&) {
            return ECANCELED;
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
        } catch (std::exception& e) {
            printf("[-] %s\n", e.what());
            return -1;
        }
    } else {
        Help();
        return -1;
    }
}

