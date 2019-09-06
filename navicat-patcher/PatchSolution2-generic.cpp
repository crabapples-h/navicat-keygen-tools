#include "PatchSolutions.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\PatchSolution2-generic.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    const char PatchSolution2::KeywordMeta[0x188 + 1] =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I"
        "qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv"
        "a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF"
        "R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2"
        "WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt"
        "YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ"
        "awIDAQAB";

    [[nodiscard]]
    bool PatchSolution2::CheckKey(const RSACipher& Cipher) const noexcept {
        auto szPublicKey = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

        for (auto pos = szPublicKey.find("-----BEGIN PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKey.find("-----BEGIN PUBLIC KEY-----", pos)) {
            szPublicKey.erase(pos, literal_length("-----BEGIN PUBLIC KEY-----"));
        }

        for (auto pos = szPublicKey.find("-----END PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKey.find("-----END PUBLIC KEY-----", pos)) {
            szPublicKey.erase(pos, literal_length("-----END PUBLIC KEY-----"));
        }

        for (auto pos = szPublicKey.find("\n"); pos != std::string::npos; pos = szPublicKey.find("\n", pos)) {
            szPublicKey.erase(pos, literal_length("\n"));
        }

        return szPublicKey.length() == literal_length(KeywordMeta);
    }

    void PatchSolution2::MakePatch(const RSACipher& Cipher) const {
        for (size_t i = 0; i < _countof(_PatchOffset); ++i) {
            if (_PatchOffset[i] == InvalidOffset) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PatchSolution2 has not been ready yet."));
            }
        }

        auto pbImage = _Image.ImageBase<uint8_t*>();
        auto szPublicKey = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

        for (auto pos = szPublicKey.find("-----BEGIN PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKey.find("-----BEGIN PUBLIC KEY-----", pos)) {
            szPublicKey.erase(pos, literal_length("-----BEGIN PUBLIC KEY-----"));
        }

        for (auto pos = szPublicKey.find("-----END PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKey.find("-----END PUBLIC KEY-----", pos)) {
            szPublicKey.erase(pos, literal_length("-----END PUBLIC KEY-----"));
        }

        for (auto pos = szPublicKey.find("\n"); pos != std::string::npos; pos = szPublicKey.find("\n", pos)) {
            szPublicKey.erase(pos, literal_length("\n"));
        }

        if (szPublicKey.length() != literal_length(KeywordMeta)) {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("szPublicKey.length() != literal_length(KeywordMeta)"));
        }

        _putts(TEXT("*******************************************************"));
        _putts(TEXT("*                   PatchSolution2                    *"));
        _putts(TEXT("*******************************************************"));

        for (size_t i = 0; i < _countof(_PatchOffset); i += 2) {
            static_assert(_countof(_PatchOffset) % 2 == 0);
            LOG_HINT(0, "+0x%.8zx: %.2x %.2x %.2x -> %.2x %.2x %.2x | +0x%.8zx: %.2x %.2x %.2x -> %.2x %.2x %.2x",
                _PatchOffset[i],
                pbImage[_PatchOffset[i]],
                pbImage[_PatchOffset[i] + 1],
                pbImage[_PatchOffset[i] + 2],
                pbImage[_PatchOffset[i]],
                pbImage[_PatchOffset[i] + 1],
                szPublicKey[i],
                _PatchOffset[i + 1],
                pbImage[_PatchOffset[i + 1]],
                pbImage[_PatchOffset[i + 1] + 1],
                pbImage[_PatchOffset[i + 1] + 2],
                pbImage[_PatchOffset[i + 1]],
                pbImage[_PatchOffset[i + 1] + 1],
                szPublicKey[i + 1]
            );

            pbImage[_PatchOffset[i] + 2] = szPublicKey[i];
            pbImage[_PatchOffset[i + 1] + 2] = szPublicKey[i + 1];
        }
    }
}

