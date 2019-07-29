#pragma once
#include <keystone/keystone.h>
#include "../common/ResourceOwned.hpp"
#include "ResourceTraitsKeystone.hpp"
#include <vector>
#include <string>

class KeystoneAssembler {
private:

    ResourceOwned<KeystoneHandleTraits> pvt_Engine;

    KeystoneAssembler() noexcept :
        pvt_Engine(KeystoneHandleTraits{}) {}
public:

    [[nodiscard]]
    static KeystoneAssembler Create(ks_arch ArchType, ks_mode Mode);

    void Option(ks_opt_type Type, size_t Value);

    [[nodiscard]]
    std::vector<uint8_t> GenerateOpcode(const char* AssemblyCode, uint64_t Address = 0) const;

    [[nodiscard]]
    std::vector<uint8_t> GenerateOpcode(const std::string& AssemblyCode, uint64_t Address = 0) const;
};

