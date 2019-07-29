#include "CapstoneDisassembler.hpp"

CapstoneDisassembler CapstoneDisassembler::Create(cs_arch ArchType, cs_mode Mode) {
    CapstoneDisassembler NewDisassembler;

    auto err = cs_open(ArchType, Mode, NewDisassembler.pvt_Handle.GetAddress());
    if (err != CS_ERR_OK) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::CapstoneError(__FILE__, __LINE__, err, "cs_open failed.");
    }

    NewDisassembler.pvt_Insn.TakeOver(cs_malloc(NewDisassembler.pvt_Handle));
    if (NewDisassembler.pvt_Insn.IsValid() == false) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::CapstoneError(__FILE__, __LINE__, cs_errno(NewDisassembler.pvt_Handle), "cs_malloc failed.");
    }

    return NewDisassembler;
}

void CapstoneDisassembler::Option(cs_opt_type Type, size_t Value) {
    auto err = cs_option(pvt_Handle, Type, Value);
    if (err != CS_ERR_OK) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::CapstoneError(__FILE__, __LINE__, err, "cs_option failed.");
    }

    pvt_CurrentInsn = nullptr;

    pvt_Insn.TakeOver(cs_malloc(pvt_Handle));
    if (pvt_Insn.IsValid() == false) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::CapstoneError(__FILE__, __LINE__, cs_errno(pvt_Handle), "cs_malloc failed.");
    }
}

void CapstoneDisassembler::SetContext(uintptr_t lpOpcode, size_t cbOpcode, uint64_t Address) noexcept {
    pvt_CurrentCtx.pbOpcode = reinterpret_cast<const uint8_t*>(lpOpcode);
    pvt_CurrentCtx.cbOpcode = cbOpcode;
    pvt_CurrentCtx.Address = Address;
    pvt_CurrentInsn = nullptr;
}

void CapstoneDisassembler::SetContext(const void* lpOpcode, size_t cbOpcode, uint64_t Address) noexcept {
    pvt_CurrentCtx.pbOpcode = reinterpret_cast<const uint8_t*>(lpOpcode);
    pvt_CurrentCtx.cbOpcode = cbOpcode;
    pvt_CurrentCtx.Address = Address;
    pvt_CurrentInsn = nullptr;
}

const CapstoneDisassembler::Context& CapstoneDisassembler::GetContext() const noexcept {
    return pvt_CurrentCtx;
}

const cs_insn* CapstoneDisassembler::GetInstruction() const noexcept {
    return pvt_CurrentInsn;
}

CapstoneDisassembler::Context CapstoneDisassembler::GetInstructionContext() const noexcept {
    Context CtxOfInsn = {};
    CtxOfInsn.pbOpcode = pvt_CurrentCtx.pbOpcode - pvt_CurrentInsn->size;
    CtxOfInsn.cbOpcode = pvt_CurrentCtx.cbOpcode + pvt_CurrentInsn->size;
    CtxOfInsn.Address = pvt_CurrentCtx.Address - pvt_CurrentInsn->size;
    return CtxOfInsn;
}

bool CapstoneDisassembler::Next() noexcept {
    bool bSucceed = cs_disasm_iter(pvt_Handle, &pvt_CurrentCtx.pbOpcode, &pvt_CurrentCtx.cbOpcode, &pvt_CurrentCtx.Address, pvt_Insn);
    if (bSucceed) {
        if (pvt_CurrentInsn == nullptr) pvt_CurrentInsn = pvt_Insn.Get();
    } else {
        pvt_CurrentInsn = nullptr;
    }
    return bSucceed;
}

