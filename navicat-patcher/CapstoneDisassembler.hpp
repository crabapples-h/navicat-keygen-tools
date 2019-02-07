#pragma once
#include <capstone/capstone.h>
#include "ResourceObject.hpp"
#include "Exception.hpp"

struct CapstoneHandleTraits {
    using HandleType = csh;
    static inline const HandleType InvalidValue = 0;
    static inline void Releasor(HandleType Handle) {
        cs_close(&Handle);
    }
};

template<typename __Type>
struct CapstoneMallocTraits {
    using HandleType = __Type*;
    static inline const HandleType InvalidValue = nullptr;
    static inline void Releasor(HandleType Handle) {
        cs_free(Handle, 1);
    }
};

class CapstoneError : public Exception {
private:
    const cs_err _ErrorCode;
public:
    CapstoneError(const char* FileName,
                  size_t Line,
                  cs_err Code,
                  const char* Message) noexcept :
        Exception(FileName, Line, Message),
        _ErrorCode(Code) {}

    virtual bool HasErrorCode() const noexcept override {
        return true;
    }

    virtual unsigned long ErrorCode() const noexcept override {
        return _ErrorCode;
    }

    virtual const char* ErrorString() const noexcept override {
        return cs_strerror(_ErrorCode);
    }
};

class CapstoneDisassembler;
class CapstoneEngine;

class CapstoneDisassembler {
    friend class CapstoneEngine;
public:

    struct Context {
        union {
            const uint8_t* ConstPtr;
            uint8_t* Ptr;
        } Opcodes;
        size_t OpcodesSize;
        uint64_t Address;

        bool operator==(const Context& Other) const noexcept {
            return memcmp(this, &Other, sizeof(Context)) == 0;
        }

        bool operator!=(const Context& Other) const noexcept {
            return memcmp(this, &Other, sizeof(Context)) != 0;
        }
    };

    static inline Context InvalidContext = {};

private:
    const CapstoneEngine&                           _$$_ConstRef_Engine;
    ResourceObject<CapstoneMallocTraits<cs_insn>>   _$$_InstructionObj;
    Context                                         _$$_Context;
    Context                                         _$$_InstructionContext;
    cs_insn*                                        _$$_Instruction;

    explicit CapstoneDisassembler(const CapstoneEngine& Engine);
public:

    void SetContext(const uint8_t* Opcodes,
                    size_t Size,
                    uint64_t Address = 0) noexcept;

    void SetContext(const Context& Context) noexcept;

    const Context& GetContext() const noexcept;

    bool Next() noexcept;

    cs_insn* GetInstruction() const noexcept;

    const Context& GetInstructionContext() const noexcept;

    ~CapstoneDisassembler();
};

class CapstoneEngine {
private:
    ResourceObject<CapstoneHandleTraits> _$$_EngineObj;
public:

    CapstoneEngine(cs_arch ArchType, cs_mode Mode);

    CapstoneEngine(const CapstoneEngine&) = delete;

    CapstoneEngine(CapstoneEngine&& Other) noexcept;

    CapstoneEngine& operator=(const CapstoneEngine&) = delete;

    CapstoneEngine& operator=(CapstoneEngine&& Other) noexcept;

    csh Handle() const noexcept;

    void Option(cs_opt_type Type, size_t Value);

    CapstoneDisassembler CreateDisassembler() const;
};

