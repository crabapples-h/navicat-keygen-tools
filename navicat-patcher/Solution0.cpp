#include "Solutions.hpp"
#include "Helper.hpp"

namespace Patcher {

    const char Solution0::Keyword[452] =
            "-----BEGIN PUBLIC KEY-----\x00"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I\x00"
            "qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv\x00"
            "a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF\x00"
            "R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2\x00"
            "WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt\x00"
            "YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ\x00"
            "awIDAQAB\x00"
            "-----END PUBLIC KEY-----\x00";

    bool Solution0::FindPatchOffset() noexcept {
        bool bFound = false;

        uint8_t* pFileView = pTargetFile->GetView<uint8_t>();
        off_t FileSize;

        if (pFileView == nullptr)
            return false;

        if (!pTargetFile->GetFileSize(FileSize))
            return false;

        if (FileSize < KeywordLength)
            return false;

        FileSize -= KeywordLength;
        for (off_t i = 0; i < FileSize; ++i) {
            if (pFileView[i] == Keyword[0] && memcmp(pFileView + i, Keyword, KeywordLength) == 0) {
                PatchOffset = i;
                bFound = true;
                break;
            }
        }

        if (bFound)
            printf("MESSAGE: [Solution0] Keyword has been found: offset = +0x%08lx.\n",
                   static_cast<unsigned long>(PatchOffset));
        return bFound;
    }

    bool Solution0::MakePatch(RSACipher* cipher) const {
        uint8_t* lpTargetFileView = pTargetFile->GetView<uint8_t>();
        std::string RSAPublicKeyPEM =
                cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();

        if (RSAPublicKeyPEM.empty()) {
            REPORT_ERROR("ERROR: cipher->ExportKeyString failed.");
            return false;
        }

        for (size_t i = 0; i < RSAPublicKeyPEM.length(); ++i) {
            if (RSAPublicKeyPEM[i] == '\n')
                RSAPublicKeyPEM[i] = '\x00';
        }

        if (RSAPublicKeyPEM.length() != KeywordLength) {
            REPORT_ERROR("ERROR: Public key length does not match.");
            return false;
        }

        PRINT_MESSAGE("//");
        PRINT_MESSAGE("// Begin Solution0");
        PRINT_MESSAGE("//");
        printf("@+0x%08llX\nPrevious:\n", PatchOffset);
        Helper::PrintMemory(lpTargetFileView + PatchOffset,
                            lpTargetFileView + PatchOffset + KeywordLength,
                            lpTargetFileView);

        memcpy(lpTargetFileView + PatchOffset, RSAPublicKeyPEM.c_str(), KeywordLength);

        PRINT_MESSAGE("After:");
        Helper::PrintMemory(lpTargetFileView + PatchOffset,
                            lpTargetFileView + PatchOffset + KeywordLength,
                            lpTargetFileView);
        PRINT_MESSAGE("");
        return true;
    }
}