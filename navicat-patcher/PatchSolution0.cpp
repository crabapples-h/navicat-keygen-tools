#include "PatchSolutions.hpp"
#include <memory.h>

const char PatchSolution0::Keyword[452] =
    "-----BEGIN PUBLIC KEY-----\x00"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I\x00"
    "qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv\x00"
    "a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF\x00"
    "R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2\x00"
    "WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt\x00"
    "YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ\x00"
    "awIDAQAB\x00"
    "-----END PUBLIC KEY-----\x00";

PatchSolution0::PatchSolution0(const X64ImageInterpreter& Image) noexcept :
    pvt_Image(Image),
    pvt_PatchOffset(X64ImageInterpreter::InvalidOffset) {}

bool PatchSolution0::FindPatchOffset() noexcept {
    try {
        pvt_PatchOffset = pvt_Image.SearchSectionOffset("__TEXT", "__cstring", [](const uint8_t* p) {
            return memcmp(p, Keyword, sizeof(Keyword) - 1) == 0;
        });

        printf("[+] PatchSolution0 ...... Ready to apply.\n");
        printf("    Keyword offset = +0x%.8x\n", pvt_PatchOffset);
        return true;
    } catch (...) {
        printf("[-] PatchSolution0 ...... Omitted.\n");
        return false;
    }
}

bool PatchSolution0::CheckKey(const RSACipher& RsaCipher) const noexcept {
    try {
        if (RsaCipher.Bits() != 2048) {
            return false;
        }

        std::string PublicKeyPEM = RsaCipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();
        for (auto& c : PublicKeyPEM) {
            if (c == '\n') c = '\x00';
        }

        return PublicKeyPEM.length() == sizeof(Keyword) - 1;
    } catch (...) {
        return false;
    }
}

void PatchSolution0::MakePatch(const RSACipher& RsaCipher) const {
    if (pvt_PatchOffset == X64ImageInterpreter::InvalidOffset) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "PatchSolution0 is not ready.");
    }

    std::string PublicKeyPEM = RsaCipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();
    for (auto& c : PublicKeyPEM) {
        if (c == '\n') c = '\x00';
    }

    auto pbPatch = pvt_Image.ImageOffset<uint8_t*>(pvt_PatchOffset);

    puts("**************************************************************");
    puts("*                      PatchSolution0                        *");
    puts("**************************************************************");
    printf("@+0x%.8x\n", pvt_PatchOffset);

    puts("Previous:");
    nkg::PrintMemory(pbPatch, pbPatch + sizeof(Keyword), pbPatch);

    memcpy(pbPatch, PublicKeyPEM.data(), PublicKeyPEM.size());

    puts("After:");
    nkg::PrintMemory(pbPatch, pbPatch + sizeof(Keyword), pbPatch);

    puts("");
}
