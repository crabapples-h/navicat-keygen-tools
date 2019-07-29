#include <string.h> // NOLINT
#include "ExceptionCapstone.hpp"
#include "CapstoneDisassembler.hpp"
#include "X64ImageInterpreter.hpp"

namespace nkg {

    bool IsResolvedTo(const X64ImageInterpreter& Image, const void* StubHelperProc, const char *Symbol) {
        CapstoneDisassembler Disassembler = CapstoneDisassembler::Create(CS_ARCH_X86, CS_MODE_64);

        Disassembler.Option(CS_OPT_DETAIL, CS_OPT_ON);

        // A stub-helper proc must look like:
        //     push xxxxh;
        //     jmp loc_xxxxxxxx
        // which should be 10 bytes long.
        Disassembler.SetContext(StubHelperProc, 10);

        if (Disassembler.Next() == false) {
            return false;
        }

        auto insn = Disassembler.GetInstruction();
        if (strcasecmp(insn->mnemonic, "push") != 0 || insn->detail->x86.operands[0].type != X86_OP_IMM) {
            return false;
        }

        auto bind_opcode_offset = static_cast<uint32_t>(insn->detail->x86.operands[0].imm);
        if (Image.CommandOf<LC_DYLD_INFO_ONLY>() == nullptr) {
            return false;
        }

        auto bind_opcode_ptr =
            Image.ImageOffset<uint8_t*>(Image.CommandOf<LC_DYLD_INFO_ONLY>()->lazy_bind_off) +
            bind_opcode_offset;

        while ((*bind_opcode_ptr & BIND_OPCODE_MASK) != BIND_OPCODE_DONE) {
            switch (*bind_opcode_ptr & BIND_OPCODE_MASK) {
                case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:         // 0x10
                case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:         // 0x30
                case BIND_OPCODE_SET_TYPE_IMM:                  // 0x50
                case BIND_OPCODE_DO_BIND:                       // 0x90
                case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:   // 0xB0
                    ++bind_opcode_ptr;
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:        // 0x20
                case BIND_OPCODE_SET_ADDEND_SLEB:               // 0x60
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:   // 0x70
                case BIND_OPCODE_ADD_ADDR_ULEB:                 // 0x80
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:         // 0xA0
                    while (*(++bind_opcode_ptr) & 0x80u);
                    ++bind_opcode_ptr;
                    break;
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: // 0x40
                    return strcmp(reinterpret_cast<const char *>(bind_opcode_ptr + 1), Symbol) == 0;
                case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:  // 0xC0
                    //
                    // This opcode is too rare to appear,
                    // It is okay to dismiss this opcode
                    //
                    return false;
                default:
                    return false;
            }
        }

        return false;
    }

}
