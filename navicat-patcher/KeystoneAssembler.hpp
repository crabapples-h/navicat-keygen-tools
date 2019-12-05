#pragma once
#include "ExceptionKeystone.hpp"
#include "ResourceWrapper.hpp"
#include "ResourceTraitsKeystone.hpp"
#include <vector>
#include <string>

namespace nkg {

    class KeystoneEngine;

    class KeystoneAssembler {
        friend class KeystoneEngine;
    private:

        const KeystoneEngine& m_Engine;

        KeystoneAssembler(const KeystoneEngine& Engine) noexcept;

    public:

        [[nodiscard]]
        std::vector<uint8_t> GenerateMachineCode(std::string_view AssemblyCode, uint64_t Address = 0) const;

    };

    class KeystoneEngine : private ARL::ResourceWrapper<ARL::ResourceTraits::KeystoneHandle> {
        friend class KeystoneAssembler;
    public:

        KeystoneEngine(ks_arch ArchType, ks_mode Mode);

        void Option(ks_opt_type Type, ks_opt_value Value);

        [[nodiscard]]
        KeystoneAssembler CreateAssembler() const;
    };

}

