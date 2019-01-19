#include "PatchSolution.hpp"
#include <tchar.h>
#include "Helper.hpp"

#undef __BASE_FILE__
#define __BASE_FILE__ "PatchSolution0.cpp"

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

bool PatchSolution0::FindPatchOffset() noexcept {
    PatchOffset = -1;

    auto PtrToResourceSectionHeader =
        _TargetFile.GetSectionHeader(".rsrc");
    auto PtrToResourceSection =
        _TargetFile.GetSectionView<uint8_t>(".rsrc");

    if (PtrToResourceSectionHeader == nullptr || 
        PtrToResourceSection == nullptr)
        return false;

    for (DWORD i = 0; i < PtrToResourceSectionHeader->SizeOfRawData; ++i) {
        if (memcmp(PtrToResourceSection + i, Keyword, KeywordLength) == 0) {
            PatchOffset = PtrToResourceSectionHeader->PointerToRawData + i;
            _tprintf_s(TEXT("MESSAGE: PatchSolution0: Keyword has been found: offset = +0x%08lx.\n"), PatchOffset);
            return true;
        }
    }

    return false;
}

bool PatchSolution0::CheckKey(RSACipher* pCipher) const {
    std::string PublicKeyPem = 
        pCipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
    Helper::ReplaceSubString(PublicKeyPem, "\n", "\r\n");
    return PublicKeyPem.length() == KeywordLength;
}

void PatchSolution0::MakePatch(RSACipher* cipher) const {
    uint8_t* pFileView = _TargetFile.GetImageBaseView<uint8_t>();
    std::string PublicKeyPEM;

    PublicKeyPEM =
        cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
    Helper::ReplaceSubString(PublicKeyPEM, "\n", "\r\n");

    _putts(TEXT("******************************************"));
    _putts(TEXT("*            PatchSulution0              *"));
    _putts(TEXT("******************************************"));
    _tprintf_s(TEXT("@ +0x%08x\nPrevious:\n"), PatchOffset);
    Helper::PrintMemory(pFileView + PatchOffset,
                        pFileView + PatchOffset + KeywordLength,
                        pFileView);

    memcpy(pFileView + PatchOffset, PublicKeyPEM.c_str(), KeywordLength);

    _putts(TEXT("After:"));
    Helper::PrintMemory(pFileView + PatchOffset,
                        pFileView + PatchOffset + KeywordLength,
                        pFileView);
}
