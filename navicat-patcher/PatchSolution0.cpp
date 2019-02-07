#include "PatchSolutions.hpp"
#include <assert.h>

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

PatchSolution0::PatchSolution0() noexcept :
    _$$_FileViewHandle(MapViewTraits::InvalidValue),
    _$$_PatchOffset(InvalidOffset) {}

void PatchSolution0::SetFile(const MapViewTraits::HandleType& FileViewHandle) noexcept {
    _$$_FileViewHandle = FileViewHandle;
    _$$_PatchOffset = InvalidOffset;
}

bool PatchSolution0::FindPatchOffset() noexcept {
    if (_$$_FileViewHandle == MapViewTraits::InvalidValue)
        return false;

    auto ViewPtr = _$$_FileViewHandle.ConstView<uint8_t>();
    size_t ViewSize = _$$_FileViewHandle.Size();

    if (ViewSize < KeywordLength)
        return false;

    _$$_PatchOffset = InvalidOffset;

    ViewSize -= KeywordLength;
    for (size_t i = 0; i < ViewSize; ++i) {
        if (ViewPtr[i] == Keyword[0] && memcmp(ViewPtr + i, Keyword, KeywordLength) == 0) {
            _$$_PatchOffset = i;
            break;
        }
    }

    if (_$$_PatchOffset != InvalidOffset) {
        printf("PatchSolution0 ...... Ready to apply.\n");
        printf("    Info: Keyword offset = +0x%08zx\n", _$$_PatchOffset);
        return true;
    } else {
        printf("PatchSolution0 ...... Omitted.\n");
        return false;
    }
}

// PatchSolution0 only requires a 2048-bit RSA key
bool PatchSolution0::CheckKey(RSACipher* pCipher) const {
    std::string PublicKeyPEM =
        pCipher->ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();
    return PublicKeyPEM.length() == KeywordLength;
}

void PatchSolution0::MakePatch(RSACipher* pCipher) const {
    if (_$$_FileViewHandle == MapViewTraits::InvalidValue || _$$_PatchOffset == InvalidOffset)
        throw Exception(__FILE__, __LINE__,
                        "PatchSolution0::MakePatch is not ready.");

    uint8_t* ViewPtr = _$$_FileViewHandle.View<uint8_t>();
    std::string PublicKeyPEM =
        pCipher->ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

    for (size_t i = 0; i < PublicKeyPEM.length(); ++i) {
        if (PublicKeyPEM[i] == '\n')
            PublicKeyPEM[i] = '\x00';
    }

    assert(PublicKeyPEM.length() == KeywordLength);

    puts("****************************");
    puts("*   Begin PatchSolution0   *");
    puts("****************************");
    printf("@+0x%08zx\n", _$$_PatchOffset);
    puts("Previous:");
    PrintMemory(ViewPtr + _$$_PatchOffset,
                ViewPtr + _$$_PatchOffset + KeywordLength,
                ViewPtr);

    memcpy(ViewPtr + _$$_PatchOffset,
           PublicKeyPEM.c_str(),
           KeywordLength);

    puts("After:");
    PrintMemory(ViewPtr + _$$_PatchOffset,
                ViewPtr + _$$_PatchOffset + KeywordLength,
                ViewPtr);
    puts("");
}

