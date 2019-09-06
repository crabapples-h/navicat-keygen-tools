#include "PatchSolutions.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\PatchSolution0.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    const char PatchSolution0::Keyword[461] =
        "-----BEGIN PUBLIC KEY-----\r\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I\r\n"
        "qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv\r\n"
        "a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF\r\n"
        "R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2\r\n"
        "WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt\r\n"
        "YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ\r\n"
        "awIDAQAB\r\n"
        "-----END PUBLIC KEY-----\r\n";

    [[nodiscard]]
    bool PatchSolution0::FindPatchOffset() noexcept {
        try {
            _PatchOffset = _Image.PointerToFileOffset(
                _Image.SearchSection<uint8_t*>(".rsrc", [](const uint8_t* p) {
                    __try {
                        return memcmp(p, Keyword, literal_length(Keyword)) == 0;
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        return false;
                    }
                })
            );

            LOG_SUCCESS(0, "PatchSolution0 ...... Ready to apply");
            LOG_HINT(4, "Patch offset = +0x%.8zx", _PatchOffset);

            return true;
        } catch (nkg::Exception&) {
            _PatchOffset = InvalidOffset;

            LOG_FAILURE(0, "PatchSolution0 ...... Omitted");

            return false;
        }
    }

    [[nodiscard]]
    bool PatchSolution0::CheckKey(const RSACipher& Cipher) const noexcept {
        auto szPublicKey = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();
        for (auto i = szPublicKey.find("\n"); i != std::string::npos; i = szPublicKey.find("\n", i + 2)) {
            szPublicKey.replace(i, 1, "\r\n");
        }

        return szPublicKey.length() == literal_length(Keyword);
    }

    void PatchSolution0::MakePatch(const RSACipher& Cipher) const {
        if (_PatchOffset == InvalidOffset) {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PatchSolution0 has not been ready yet."));
        }

        auto szPublicKey = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();
        for (auto i = szPublicKey.find("\n"); i != std::string::npos; i = szPublicKey.find("\n", i + 2)) {
            szPublicKey.replace(i, 1, "\r\n");
        }

        _putts(TEXT("*******************************************************"));
        _putts(TEXT("*                   PatchSolution0                    *"));
        _putts(TEXT("*******************************************************"));

        LOG_HINT(0, "Previous:");
        PrintMemory(_Image.ImageOffset(_PatchOffset), literal_length(Keyword), _Image.ImageBase());

        memcpy(_Image.ImageOffset(_PatchOffset), szPublicKey.c_str(), literal_length(Keyword));

        LOG_HINT(0, "After:");
        PrintMemory(_Image.ImageOffset(_PatchOffset), literal_length(Keyword), _Image.ImageBase());

        _putts(TEXT(""));
    }
}

