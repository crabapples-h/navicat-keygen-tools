#pragma once
#include <keystone/keystone.h>
#include "ResourceObject.hpp"
#include "Exception.hpp"
#include <vector>
#include <string>

struct KeystoneHandleTraits {
    using HandleType = ks_engine*;
    static inline const HandleType InvalidValue = nullptr;
    static constexpr auto& Releasor = ks_close;
};

class KeystoneError : public Exception {
private:
    const ks_err _ErrorCode;
public:

    KeystoneError(const char* FileName, size_t Line, ks_err Code, const char* Message) noexcept :
        Exception(FileName, Line, Message),
        _ErrorCode(Code) {}

    virtual bool HasErrorCode() const noexcept override {
        return true;
    }

    virtual unsigned long ErrorCode() const noexcept override {
        return _ErrorCode;
    }

    virtual const char* ErrorString() const noexcept override {
        return ks_strerror(_ErrorCode);
    }
};

class KeystoneAssembler;
class KeystoneEngine;

class KeystoneAssembler {
    friend class KeystoneEngine;
private:
    const KeystoneEngine& _$$_ConstRef_Engine;

    explicit KeystoneAssembler(const KeystoneEngine& Engine);
public:

    std::vector<uint8_t> OpCodes(const char* AssemblyCode, uint64_t Address = 0) const;

    std::vector<uint8_t> OpCodes(const std::string& AssemblyCode, uint64_t Address = 0) const;

};

class KeystoneEngine {
private:
    ResourceObject<KeystoneHandleTraits> _$$_EngineObj;
public:

    KeystoneEngine(ks_arch Arch, ks_mode Mode);

    KeystoneEngine(const KeystoneEngine&) = delete;

    KeystoneEngine(KeystoneEngine&& Other) noexcept;

    KeystoneEngine& operator=(const KeystoneEngine&) = delete;

    KeystoneEngine& operator=(KeystoneEngine&& Other) noexcept;

    ks_engine* Handle() const noexcept;

    void Option(ks_opt_type Type, size_t Value);

    KeystoneAssembler CreateAssembler() const;
};

