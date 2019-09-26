#pragma once
#include "ExceptionCapstone.hpp"
#include <ResourceOwned.hpp>
#include "ResourceTraitsCapstone.hpp"

namespace nkg {

    struct CapstoneContext {
        const void* lpMachineCode;
        size_t      cbMachineCode;
        uint64_t    Address;
    };

    class CapstoneEngine;

    class CapstoneDisassembler : private ResourceOwned<CapstoneInsnTraits> {
        friend class CapstoneEngine;
    private:

        const CapstoneEngine&   _Engine;
        CapstoneContext         _CurrentState;
        CapstoneContext         _NextState;
        cs_insn*                _lpCurrentInsn;

        CapstoneDisassembler(const CapstoneEngine& Engine);

    public:

        CapstoneDisassembler(CapstoneDisassembler&& Other) noexcept;

        CapstoneDisassembler& SetContext(const CapstoneContext& Ctx) noexcept;

        [[nodiscard]]
        const CapstoneContext& GetContext() const noexcept;

        [[nodiscard]]
        bool Next() noexcept;

        [[nodiscard]]
        const cs_insn* GetInstruction() const noexcept;

        [[nodiscard]]
        const CapstoneContext& GetInstructionContext() const noexcept;
    };

    class CapstoneEngine : private ResourceOwned<CapstoneHandleTraits> {
        friend class CapstoneDisassembler;
    public:

        CapstoneEngine(cs_arch ArchType, cs_mode Mode);

        void Option(cs_opt_type Type, cs_opt_value Value);

        [[nodiscard]]
        CapstoneDisassembler CreateDisassembler() const;
    };

}

