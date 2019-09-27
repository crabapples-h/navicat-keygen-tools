#include "PatchSolutions.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\PatchSolution4-generic.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    bool PatchSolution4::CheckKey(const RSACipher& Cipher) const noexcept {
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

        return szPublicKey.length() == 0x188;
    }

    void PatchSolution4::MakePatch(const RSACipher& Cipher) const {
        if (_pbPatchMachineCode == nullptr || _pbPatchNewPublicKey == nullptr || _NewMachineCode.empty()) {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PatchSolution4 has not been ready yet."));
        }

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

        _putts(TEXT("*******************************************************"));
        _putts(TEXT("*                   PatchSolution4                    *"));
        _putts(TEXT("*******************************************************"));

        LOG_HINT(0, "Previous:");
        PrintMemory(_pbPatchMachineCode, _NewMachineCode.size(), _Image.ImageBase());

        memcpy(_pbPatchMachineCode, _NewMachineCode.data(), _NewMachineCode.size());

        LOG_HINT(0, "After:");
        PrintMemory(_pbPatchMachineCode, _NewMachineCode.size(), _Image.ImageBase());

        _putts(TEXT(""));

        LOG_HINT(0, "Previous:");
        PrintMemory(_pbPatchNewPublicKey, szPublicKey.size(), _Image.ImageBase());

        memcpy(_pbPatchNewPublicKey, szPublicKey.data(), szPublicKey.size());

        LOG_HINT(0, "After:");
        PrintMemory(_pbPatchNewPublicKey, szPublicKey.size(), _Image.ImageBase());

        _putts(TEXT(""));
    }
}

