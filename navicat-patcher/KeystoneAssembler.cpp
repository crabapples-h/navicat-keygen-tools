#include "KeystoneAssembler.hpp"

KeystoneAssembler::KeystoneAssembler(const KeystoneEngine& Engine) :
    _$$_ConstRef_Engine(Engine) {}

std::vector<uint8_t> KeystoneAssembler::OpCodes(const char* AssemblyCode, uint64_t Address) const {
    std::vector<uint8_t> result;
    uint8_t* op_codes = nullptr;
    size_t op_codes_size = 0;
    size_t count;

    if (ks_asm(_$$_ConstRef_Engine.Handle(),
               AssemblyCode,
               Address,
               &op_codes,
               &op_codes_size,
               &count) != 0) {
        throw KeystoneError(__FILE__, __LINE__, ks_errno(_$$_ConstRef_Engine.Handle()),
                            "ks_asm fails.");
    }

    result.assign(op_codes, op_codes + op_codes_size);

    ks_free(op_codes);

    return result;
}

std::vector<uint8_t> KeystoneAssembler::OpCodes(const std::string& AssemblyCode, uint64_t Address) const {
    return OpCodes(AssemblyCode.c_str(), Address);
}

KeystoneEngine::KeystoneEngine(ks_arch ArchType, ks_mode Mode) {
    ks_err status;
    ks_engine* handle = nullptr;

    status = ks_open(ArchType, Mode, &handle);
    if (status != KS_ERR_OK)
        throw KeystoneError(__FILE__, __LINE__, status,
                            "ks_open fails.");
    else
        _$$_EngineObj.TakeOver(handle);
}

KeystoneEngine::KeystoneEngine(KeystoneEngine&& Other) noexcept :
    _$$_EngineObj(std::move(Other._$$_EngineObj)) {}

KeystoneEngine& KeystoneEngine::operator=(KeystoneEngine&& Other) noexcept {
    _$$_EngineObj = std::move(Other._$$_EngineObj);
    return *this;
}

ks_engine* KeystoneEngine::Handle() const noexcept {
    return _$$_EngineObj;
}

void KeystoneEngine::Option(ks_opt_type Type, size_t Value) {
    ks_err status;
    status = ks_option(_$$_EngineObj, Type, Value);
    if (status != KS_ERR_OK)
        throw KeystoneError(__FILE__, __LINE__, status,
                            "ks_open fails.");
}

KeystoneAssembler KeystoneEngine::CreateAssembler() const {
    return KeystoneAssembler(*this);
}

