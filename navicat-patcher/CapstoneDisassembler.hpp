#pragma once
#include <capstone/capstone.h>
#include "ExceptionCapstone.hpp"
#include "ResourceWrapper.hpp"
#include "ResourceTraitsCapstone.hpp"

namespace nkg {

    struct CapstoneContext {
        const void* lpMachineCode;
        size_t      cbMachineCode;
        uint64_t    Address;
    };

    class CapstoneEngine;

    class CapstoneDisassembler : private ARL::ResourceWrapper<ARL::ResourceTraits::CapstoneInsn> {
        friend class CapstoneEngine;
    private:

        const CapstoneEngine&   m_Engine;
        CapstoneContext         m_CurrentState;
        CapstoneContext         m_NextState;
        cs_insn*                m_lpCurrentInsn;

        CapstoneDisassembler(const CapstoneEngine& Engine);

    public:

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

    class CapstoneEngine : private ARL::ResourceWrapper<ARL::ResourceTraits::CapstoneHandle> {
        friend class CapstoneDisassembler;
    public:

        CapstoneEngine(cs_arch ArchType, cs_mode Mode);

        void Option(cs_opt_type Type, cs_opt_value Value);

        const char* GetGroupName(unsigned int group_id) const noexcept;

        const char* GetInstructionName(unsigned int instruction_id) const noexcept;

        const char* GetRegisterName(unsigned int register_id) const noexcept;

        [[nodiscard]]
        CapstoneDisassembler CreateDisassembler() const;
    };

}

