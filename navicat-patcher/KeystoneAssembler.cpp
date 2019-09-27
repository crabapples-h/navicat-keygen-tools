#include "KeystoneAssembler.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\KeystoneAssembler.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    KeystoneAssembler::KeystoneAssembler(const KeystoneEngine& Engine) noexcept :
        _Engine(Engine) {}

    [[nodiscard]]
    std::vector<uint8_t> KeystoneAssembler::GenerateMachineCode(const char* AssemblyCode, uint64_t Address) const {
        ResourceOwned   pbMachineCode(KeystoneMallocTraits{});
        size_t          cbMachineCode = 0;
        size_t          InstructionsProcessed = 0;

        if (ks_asm(_Engine, AssemblyCode, Address, pbMachineCode.GetAddressOf(), &cbMachineCode, &InstructionsProcessed) != 0) {
            throw KeystoneError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), ks_errno(_Engine), TEXT("ks_asm failed."));
        }

        return std::vector<uint8_t>(pbMachineCode.Get(), pbMachineCode.Get() + cbMachineCode);
    }

    KeystoneEngine::KeystoneEngine(ks_arch ArchType, ks_mode Mode) {
        auto err = ks_open(ArchType, Mode, GetAddressOf());
        if (err != KS_ERR_OK) {
            throw KeystoneError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), err, TEXT("ks_open failed."));
        }
    }

    void KeystoneEngine::Option(ks_opt_type Type, ks_opt_value Value) {
        auto err = ks_option(Get(), Type, Value);
        if (err != KS_ERR_OK) {
            throw KeystoneError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), err, TEXT("ks_option failed."));
        }
    }

    KeystoneAssembler KeystoneEngine::CreateAssembler() const {
        return KeystoneAssembler(*this);
    }
}

