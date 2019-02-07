#include "CapstoneDisassembler.hpp"

CapstoneDisassembler::CapstoneDisassembler(const CapstoneEngine& Engine) :
    _$$_ConstRef_Engine(Engine),
    _$$_Context(InvalidContext),
    _$$_InstructionContext(InvalidContext),
    _$$_Instruction(nullptr)
{
    cs_insn* insn;
    insn = cs_malloc(_$$_ConstRef_Engine.Handle());
    if (insn == nullptr)
        throw CapstoneError(__FILE__, __LINE__, cs_errno(_$$_ConstRef_Engine.Handle()),
                            "cs_malloc fails.");
    else
        _$$_InstructionObj.TakeOver(insn);
}

void CapstoneDisassembler::SetContext(const uint8_t* Opcodes, size_t Size, uint64_t Address) noexcept {
    _$$_Context.Opcodes.ConstPtr = Opcodes;
    _$$_Context.OpcodesSize = Size;
    _$$_Context.Address = Address;
    _$$_InstructionContext = InvalidContext;
    _$$_Instruction = nullptr;
}

void CapstoneDisassembler::SetContext(const CapstoneDisassembler::Context& Context) noexcept {
    _$$_Context = Context;
    _$$_InstructionContext = InvalidContext;
    _$$_Instruction = nullptr;
}

const CapstoneDisassembler::Context& CapstoneDisassembler::GetContext() const noexcept {
    return _$$_Context;
}

bool CapstoneDisassembler::Next() noexcept {
    Context InstructionContext = _$$_Context;
    bool bSucceed = cs_disasm_iter(_$$_ConstRef_Engine.Handle(),
                                   &_$$_Context.Opcodes.ConstPtr,
                                   &_$$_Context.OpcodesSize,
                                   &_$$_Context.Address,
                                   _$$_InstructionObj);
    if (bSucceed) {
        _$$_InstructionContext = InstructionContext;
        if (_$$_Instruction == nullptr)
            _$$_Instruction = _$$_InstructionObj;
    } else {
        _$$_InstructionContext = InvalidContext;
        _$$_Instruction = nullptr;
    }
    return bSucceed;
}

cs_insn* CapstoneDisassembler::GetInstruction() const noexcept {
    return _$$_Instruction;
}

const CapstoneDisassembler::Context& CapstoneDisassembler::GetInstructionContext() const noexcept {
    return _$$_InstructionContext;
}

CapstoneDisassembler::~CapstoneDisassembler() {
    _$$_Context = InvalidContext;
    _$$_InstructionContext = InvalidContext;
    _$$_Instruction = nullptr;
}

CapstoneEngine::CapstoneEngine(cs_arch ArchType, cs_mode Mode) {
    cs_err status;
    csh handle;

    status = cs_open(ArchType, Mode, &handle);
    if (status != CS_ERR_OK)
        throw CapstoneError(__FILE__, __LINE__, status,
                            "cs_open fails.");
    else
        _$$_EngineObj.TakeOver(handle);
}

CapstoneEngine::CapstoneEngine(CapstoneEngine&& Other) noexcept :
    _$$_EngineObj(std::move(Other._$$_EngineObj)) {}

CapstoneEngine& CapstoneEngine::operator=(CapstoneEngine&& Other) noexcept {
    _$$_EngineObj = std::move(Other._$$_EngineObj);
    return *this;
}

csh CapstoneEngine::Handle() const noexcept {
    return _$$_EngineObj;
}

void CapstoneEngine::Option(cs_opt_type Type, size_t Value) {
    cs_err status;
    status = cs_option(_$$_EngineObj, Type, Value);
    if (status != CS_ERR_OK)
        throw CapstoneError(__FILE__, __LINE__, status,
                            "cs_open fails.");
}

CapstoneDisassembler CapstoneEngine::CreateDisassembler() const {
    return CapstoneDisassembler(*this);
}

