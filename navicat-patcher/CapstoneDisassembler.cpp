#include "CapstoneDisassembler.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\CapstoneDisassembler.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    CapstoneDisassembler::CapstoneDisassembler(const CapstoneEngine& Engine) :
        ResourceOwned<CapstoneInsnTraits>(cs_malloc(Engine)),
        _Engine(Engine),
        _CurrentState{},
        _NextState{},
        _lpCurrentInsn(nullptr)
    {
        if (IsValid() == false) {
            throw CapstoneError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), cs_errno(Engine), TEXT("cs_malloc failed."));
        }
    }

    CapstoneDisassembler::CapstoneDisassembler(CapstoneDisassembler&& Other) noexcept :
        ResourceOwned<CapstoneInsnTraits>(static_cast<ResourceOwned<CapstoneInsnTraits>&&>(Other)),
        _Engine(Other._Engine),
        _CurrentState(Other._CurrentState),
        _NextState(Other._NextState),
        _lpCurrentInsn(Other._lpCurrentInsn) {}

    CapstoneDisassembler& CapstoneDisassembler::SetContext(const CapstoneContext& Ctx) noexcept {
        _lpCurrentInsn = nullptr;

        _CurrentState.lpMachineCode = nullptr;
        _CurrentState.cbMachineCode = 0;
        _CurrentState.Address = 0;

        _NextState = Ctx;

        return *this;
    }

    [[nodiscard]]
    const CapstoneContext& CapstoneDisassembler::GetContext() const noexcept {
        return _NextState;
    }

    [[nodiscard]]
    bool CapstoneDisassembler::Next() noexcept {
        bool bSucceed;
        CapstoneContext backup = _NextState;

        bSucceed = cs_disasm_iter(_Engine.Get(), reinterpret_cast<const uint8_t**>(&_NextState.lpMachineCode), &_NextState.cbMachineCode, &_NextState.Address, Get());
        if (bSucceed) {
            if (_lpCurrentInsn == nullptr) {
                _lpCurrentInsn = Get();
            }

            _CurrentState = backup;
        } else {
            _lpCurrentInsn = nullptr;
        }

        return bSucceed;
    }

    [[nodiscard]]
    const cs_insn* CapstoneDisassembler::GetInstruction() const noexcept {
        return _lpCurrentInsn;
    }

    [[nodiscard]]
    const CapstoneContext& CapstoneDisassembler::GetInstructionContext() const noexcept {
        return _CurrentState;
    }

    CapstoneEngine::CapstoneEngine(cs_arch ArchType, cs_mode Mode) {
        auto err = cs_open(ArchType, Mode, GetAddressOf());
        if (err != CS_ERR_OK) {
            throw CapstoneError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), err, TEXT("cs_open failed."));
        }
    }

    void CapstoneEngine::Option(cs_opt_type Type, cs_opt_value Value) {
        auto err = cs_option(Get(), Type, Value);
        if (err != CS_ERR_OK) {
            throw CapstoneError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), err, TEXT("cs_option failed."));
        }
    }

    [[nodiscard]]
    CapstoneDisassembler CapstoneEngine::CreateDisassembler() const {
        return CapstoneDisassembler(*this);
    }
}

