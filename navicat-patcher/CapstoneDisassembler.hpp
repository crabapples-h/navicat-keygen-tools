#pragma once
#include <capstone/capstone.h>
#include "../common/ResourceOwned.hpp"
#include "ResourceTraitsCapstone.hpp"

class CapstoneDisassembler {
public:

    struct Context {
        const uint8_t*  pbOpcode;
        size_t          cbOpcode;
        uint64_t        Address;
    };

private:

    ResourceOwned<CapstoneHandleTraits> pvt_Handle;
    ResourceOwned<CapstoneInsnTraits>   pvt_Insn;
    Context                             pvt_CurrentCtx;
    cs_insn*                            pvt_CurrentInsn;

    CapstoneDisassembler() noexcept :
        pvt_Handle(CapstoneHandleTraits{}),
        pvt_Insn(CapstoneInsnTraits{}),
        pvt_CurrentCtx{},
        pvt_CurrentInsn(nullptr) {}
public:

    [[nodiscard]]
    static CapstoneDisassembler Create(cs_arch ArchType, cs_mode Mode);

    void Option(cs_opt_type Type, size_t Value);

    void SetContext(uintptr_t lpOpcode, size_t cbOpcode, uint64_t Address = 0) noexcept ;

    void SetContext(const void* lpOpcode, size_t cbOpcode, uint64_t Address = 0) noexcept;

    [[nodiscard]]
    const Context& GetContext() const noexcept;

    [[nodiscard]]
    const cs_insn* GetInstruction() const noexcept;

    [[nodiscard]]
    Context GetInstructionContext() const noexcept;

    [[nodiscard]]
    bool Next() noexcept;
};
