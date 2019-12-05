#include "CapstoneDisassembler.hpp"

namespace nkg {

    CapstoneDisassembler::CapstoneDisassembler(const CapstoneEngine& Engine) :
        ARL::ResourceWrapper<ARL::ResourceTraits::CapstoneInsn>(cs_malloc(Engine)),
        m_Engine(Engine),
        m_CurrentState{},
        m_NextState{},
        m_lpCurrentInsn(nullptr)
    {
        if (IsValid() == false) {
            throw ARL::CapstoneError(__BASE_FILE__, __LINE__, cs_errno(Engine), "cs_malloc failed.");
        }
    }

    CapstoneDisassembler& CapstoneDisassembler::SetContext(const CapstoneContext& Ctx) noexcept {
        m_lpCurrentInsn = nullptr;

        m_CurrentState.lpMachineCode = nullptr;
        m_CurrentState.cbMachineCode = 0;
        m_CurrentState.Address = 0;

        m_NextState = Ctx;

        return *this;
    }

    [[nodiscard]]
    const CapstoneContext& CapstoneDisassembler::GetContext() const noexcept {
        return m_NextState;
    }

    [[nodiscard]]
    bool CapstoneDisassembler::Next() noexcept {
        bool bSucceed;
        CapstoneContext backup = m_NextState;

        bSucceed = cs_disasm_iter(m_Engine.Get(), reinterpret_cast<const uint8_t**>(&m_NextState.lpMachineCode), &m_NextState.cbMachineCode, &m_NextState.Address, Get());
        if (bSucceed) {
            if (m_lpCurrentInsn == nullptr) {
                m_lpCurrentInsn = Get();
            }

            m_CurrentState = backup;
        } else {
            m_lpCurrentInsn = nullptr;
        }

        return bSucceed;
    }

    [[nodiscard]]
    const cs_insn* CapstoneDisassembler::GetInstruction() const noexcept {
        return m_lpCurrentInsn;
    }

    [[nodiscard]]
    const CapstoneContext& CapstoneDisassembler::GetInstructionContext() const noexcept {
        return m_CurrentState;
    }

    CapstoneEngine::CapstoneEngine(cs_arch ArchType, cs_mode Mode) {
        auto err = cs_open(ArchType, Mode, GetAddressOf());
        if (err != CS_ERR_OK) {
            throw ARL::CapstoneError(__BASE_FILE__, __LINE__, err, "cs_open failed.");
        }
    }

    void CapstoneEngine::Option(cs_opt_type Type, cs_opt_value Value) {
        auto err = cs_option(Get(), Type, Value);
        if (err != CS_ERR_OK) {
            throw ARL::CapstoneError(__BASE_FILE__, __LINE__, err, "cs_option failed.");
        }
    }

    const char* CapstoneEngine::GetGroupName(unsigned int group_id) const noexcept {
        return cs_group_name(Get(), group_id);
    }

    const char* CapstoneEngine::GetInstructionName(unsigned int instruction_id) const noexcept {
        return cs_insn_name(Get(), instruction_id);
    }

    const char* CapstoneEngine::GetRegisterName(unsigned int register_id) const noexcept {
        return cs_reg_name(Get(), register_id);
    }

    [[nodiscard]]
    CapstoneDisassembler CapstoneEngine::CreateDisassembler() const {
        return CapstoneDisassembler(*this);
    }

}

