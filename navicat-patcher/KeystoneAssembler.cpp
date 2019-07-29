#include "KeystoneAssembler.hpp"

[[nodiscard]]
KeystoneAssembler KeystoneAssembler::Create(ks_arch ArchType, ks_mode Mode) {
    KeystoneAssembler NewAssembler;

    auto err = ks_open(ArchType, Mode, NewAssembler.pvt_Engine.GetAddress());
    if (err != KS_ERR_OK) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::KeystoneError(__FILE__, __LINE__, err, "ks_open failed.");
    }

    return NewAssembler;
}

void KeystoneAssembler::Option(ks_opt_type Type, size_t Value) {
    auto err = ks_option(pvt_Engine, Type, Value);
    if (err != KS_ERR_OK) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::KeystoneError(__FILE__, __LINE__, err, "ks_open failed.");
    }
}

[[nodiscard]]
std::vector<uint8_t> KeystoneAssembler::GenerateOpcode(const char *AssemblyCode, uint64_t Address) const {
    ResourceOwned pbOpcode(KeystoneMallocTraits{});
    size_t cbOpCode = 0;
    size_t InstructionsProcessed = 0;

    if (ks_asm(pvt_Engine, AssemblyCode, Address, pbOpcode.GetAddress(), &cbOpCode, &InstructionsProcessed) != 0) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::KeystoneError(__FILE__, __LINE__, ks_errno(pvt_Engine), "ks_asm failed.");
    }

    return std::vector<uint8_t>(pbOpcode.Get(), pbOpcode.Get() + cbOpCode);
}

[[nodiscard]]
std::vector<uint8_t> KeystoneAssembler::GenerateOpcode(const std::string& AssemblyCode, uint64_t Address) const {
    ResourceOwned pbOpcode(KeystoneMallocTraits{});
    size_t cbOpCode = 0;
    size_t InstructionsProcessed = 0;

    if (ks_asm(pvt_Engine, AssemblyCode.c_str(), Address, pbOpcode.GetAddress(), &cbOpCode, &InstructionsProcessed) != 0) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::KeystoneError(__FILE__, __LINE__, ks_errno(pvt_Engine), "ks_asm failed.");
    }

    return std::vector<uint8_t>(pbOpcode.Get(), pbOpcode.Get() + cbOpCode);
}
