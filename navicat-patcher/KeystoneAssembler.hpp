#pragma once
#include "ExceptionKeystone.hpp"
#include <ResourceOwned.hpp>
#include "ResourceTraitsKeystone.hpp"
#include <vector>

namespace nkg {

    class KeystoneEngine;

    class KeystoneAssembler {
        friend class KeystoneEngine;
    private:

        const KeystoneEngine& _Engine;

        KeystoneAssembler(const KeystoneEngine& Engine) noexcept;

    public:

        [[nodiscard]]
        std::vector<uint8_t> GenerateMachineCode(const char* AssemblyCode, uint64_t Address = 0) const;

    };

    class KeystoneEngine : private ResourceOwned<KeystoneHandleTraits> {
        friend class KeystoneAssembler;
    public:

        KeystoneEngine(ks_arch ArchType, ks_mode Mode);

        void Option(ks_opt_type Type, ks_opt_value Value);

        [[nodiscard]]
        KeystoneAssembler CreateAssembler() const;
    };

}

