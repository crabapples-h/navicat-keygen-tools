#include "KeystoneAssembler.hpp"

namespace nkg {

    KeystoneAssembler::KeystoneAssembler(const KeystoneEngine& Engine) noexcept :
        m_Engine(Engine) {}

    [[nodiscard]]
    std::vector<uint8_t> KeystoneAssembler::GenerateMachineCode(std::string_view AssemblyCode, uint64_t Address) const {
        ARL::ResourceWrapper    pbMachineCode(ARL::ResourceTraits::KeystoneMalloc{});
        size_t                  cbMachineCode = 0;
        size_t                  InstructionsProcessed = 0;

        if (ks_asm(m_Engine, AssemblyCode.data(), Address, pbMachineCode.GetAddressOf(), &cbMachineCode, &InstructionsProcessed) != 0) {
            throw ARL::KeystoneError(__BASE_FILE__, __LINE__, ks_errno(m_Engine), "ks_asm failed.");
        }

        return std::vector<uint8_t>(pbMachineCode.Get(), pbMachineCode.Get() + cbMachineCode);
    }

    KeystoneEngine::KeystoneEngine(ks_arch ArchType, ks_mode Mode) {
        auto err = ks_open(ArchType, Mode, GetAddressOf());
        if (err != KS_ERR_OK) {
            throw ARL::KeystoneError(__BASE_FILE__, __LINE__, err, "ks_open failed.");
        }
    }

    void KeystoneEngine::Option(ks_opt_type Type, ks_opt_value Value) {
        auto err = ks_option(Get(), Type, Value);
        if (err != KS_ERR_OK) {
            throw ARL::KeystoneError(__BASE_FILE__, __LINE__, err, "ks_option failed.");
        }
    }

    KeystoneAssembler KeystoneEngine::CreateAssembler() const {
        return KeystoneAssembler(*this);
    }

}

