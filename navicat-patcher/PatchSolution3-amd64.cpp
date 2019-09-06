#include "PatchSolutions.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\PatchSolution3-amd64.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    PatchSolution3::PatchSolution3(const ImageInterpreter& Image) :
        _Image(Image),
        _Engine(CS_ARCH_X86, CS_MODE_64),
        _Patch{} 
    {
        _Engine.Option(CS_OPT_DETAIL, CS_OPT_ON);
    }

    PatchSolution3::PatchSolution3(const ImageInterpreter* lpImage) :
        _Image(*lpImage),
        _Engine(CS_ARCH_X86, CS_MODE_64),
        _Patch{} 
    {
        _Engine.Option(CS_OPT_DETAIL, CS_OPT_ON);
    }

    [[nodiscard]]
    bool PatchSolution3::CheckIfMatchPattern(const cs_insn* lpInsn) const noexcept {
        // the instruction we're interested in has one of the following patterns:
        //  1. mov PTR [MEM], IMM   (IMM must consist of printable chars)               // for IMM_DATA
        //  2. lea REG, PTR [MEM]   (MEM must point to a non-empty printable string)    // for STRING_DATA

        if (_stricmp(lpInsn->mnemonic, "mov") == 0) {
            if (lpInsn->detail->x86.operands[1].type != X86_OP_IMM) {
                return false;
            }

            auto pbImmValue = lpInsn->bytes + lpInsn->detail->x86.encoding.imm_offset;
            auto cbImmValue = lpInsn->detail->x86.encoding.imm_size;

            return IsPrintable(pbImmValue, cbImmValue);
        } else if (_stricmp(lpInsn->mnemonic, "lea") == 0) {
            // as far as I know, all strings are loaded by "lea REG, QWORD PTR [RIP + disp]"
            // so operands[1] must look like "[RIP + disp]"
            if (lpInsn->detail->x86.operands[1].mem.base != X86_REG_RIP) {
                return false;
            }

            // scale must 1, otherwise pattern mismatches
            if (lpInsn->detail->x86.operands[1].mem.scale != 1) {
                return false;
            }

            auto StringRva = static_cast<uintptr_t>(
                lpInsn->address + lpInsn->size +            // Next RIP
                lpInsn->detail->x86.operands[1].mem.disp
            );

            try {
                auto StringPtr = _Image.RvaToPointer<const char*>(StringRva);
                auto StringLength = strlen(StringPtr);

                // StringPtr must have at least one char
                // every char in StringPtr must be printable, otherwise pattern mismatches
                return StringLength && IsPrintable(StringPtr, StringLength);
            } catch (nkg::Exception&) {
                // If not found, pattern mismatches
                return false;
            }
        } else {
            return false;
        }
    }

    [[nodiscard]]
    bool PatchSolution3::CheckIfFound(const cs_insn* lpInsn, size_t KeywordIdx) const noexcept {
        // the instruction we're interested in has one of the following patterns:
        //  1. mov PTR [MEM], IMM   (IMM must consist of printable chars)               // for IMM_DATA
        //  2. lea REG, PTR [MEM]   (MEM must point to a non-empty printable string)    // for STRING_DATA

        auto& op_count = lpInsn->detail->x86.op_count;
        auto& operands = lpInsn->detail->x86.operands;

        if (op_count != 2) {
            return false;
        }

        if (Keyword[KeywordIdx].Type == IMM_DATA && operands[1].type == X86_OP_IMM) {
            static_assert(sizeof(operands[1].imm) == sizeof(Keyword[KeywordIdx].Value));
            return
                operands[1].imm == *reinterpret_cast<const int64_t*>(Keyword[KeywordIdx].Value) &&
                lpInsn->detail->x86.encoding.imm_size == Keyword[KeywordIdx].Size;
        } else if (Keyword[KeywordIdx].Type == STRING_DATA && operands[1].type == X86_OP_MEM) {
            auto StringRva = static_cast<uintptr_t>(
                lpInsn->address + lpInsn->size +            // Next RIP
                operands[1].mem.disp
            );

            try {
                auto StringPtr = _Image.RvaToPointer<const char*>(StringRva);
                return 
                    strncmp(StringPtr, reinterpret_cast<const char*>(Keyword[KeywordIdx].Value), Keyword[KeywordIdx].Size) == 0 &&
                    StringPtr[Keyword[KeywordIdx].Size] == '\x00';
            } catch (nkg::Exception&) {
                return false;
            }
        } else {
            return false;
        }
    }

    [[nodiscard]]
    PatchSolution3::PatchInfo PatchSolution3::CreatePatchPoint(const void* lpOpcode, const cs_insn* lpInsn, size_t KeywordIdx) const noexcept {
        PatchInfo NewPatch;

        NewPatch.OpcodeRva = lpInsn->address;
        NewPatch.lpOpcode = const_cast<void*>(lpOpcode);

        if (lpInsn->detail->x86.operands[1].type == X86_OP_MEM) {
            auto StringRva = static_cast<uintptr_t>(
                lpInsn->address + lpInsn->size +            // Next RIP
                lpInsn->detail->x86.operands[1].mem.disp
            );

            NewPatch.lpOriginalString = _Image.RvaToPointer<char*>(StringRva);

            if (Keyword[KeywordIdx].NotRecommendedToModify) {
                NewPatch.lpPatch = address_offset(NewPatch.lpOpcode, lpInsn->detail->x86.encoding.disp_offset);
                NewPatch.cbPatch = lpInsn->detail->x86.encoding.disp_size;
            } else {
                NewPatch.lpPatch = reinterpret_cast<uint8_t*>(NewPatch.lpOriginalString);
                NewPatch.cbPatch = Keyword[KeywordIdx].Size;
            }
        } else {                                            // X86_OP_IMM
            NewPatch.lpPatch = address_offset(NewPatch.lpOpcode, lpInsn->detail->x86.encoding.imm_offset);
            NewPatch.cbPatch = lpInsn->detail->x86.encoding.imm_size;
            NewPatch.lpOriginalString = nullptr;
        }

        NewPatch.lpReplaceString = nullptr;

        return NewPatch;
    }

    [[nodiscard]]
    bool PatchSolution3::FindPatchOffset() noexcept {
        try {
            static const uint8_t HeaderOfTargetFunction[] = {
                0x40, 0x55,                                         // push    rbp
                0x48, 0x8D, 0xAC, 0x24, 0x70, 0xBC, 0xFF, 0xFF,     // lea     rbp, [rsp-4390h]
                0xB8, 0x90, 0x44, 0x00, 0x00                        // mov     eax, 4490h
            };

            PatchInfo Patch[_countof(_Patch)] = {};

            const uint8_t* lpTargetFunction = nullptr;
            auto lptargetFunctionHint = _Image.SearchSection<const uint8_t*>(".text", [&lpTargetFunction](const uint8_t* p) {
                __try {
                    if (*reinterpret_cast<const uint32_t*>(p) == 0x6b67424e) {
                        auto i = p - 0x250;
                        for (; i < p; ++i) {
                            if (memcmp(i, HeaderOfTargetFunction, sizeof(HeaderOfTargetFunction)) == 0) {
                                lpTargetFunction = i;
                                return true;
                            }
                        }
                    }

                    return false;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            });

            size_t KeywordIndex = 0;
            CapstoneDisassembler Disassembler = _Engine.CreateDisassembler();

            Disassembler.SetContext(CapstoneContext{ lpTargetFunction, 0xcd03, _Image.PointerToRva(lpTargetFunction) });

            while (Disassembler.Next()) {
                auto lpInsn = Disassembler.GetInstruction();

                if (lpInsn->mnemonic[0] == 'j' || lpInsn->mnemonic[0] == 'J') {
                    auto JumpedBranch = GetJumpedBranch(Disassembler.GetContext(), lpInsn);

                    if (_stricmp(lpInsn->mnemonic, "jmp") == 0) {
                        Disassembler.SetContext(JumpedBranch);
                    } else {
                        Disassembler.SetContext(SelectBranch(Disassembler.GetContext(), JumpedBranch, KeywordIndex));
                    }
                } else if (_stricmp(lpInsn->mnemonic, "ret") == 0) {
                    throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Reach end of function."));
                } else {
                    if (CheckIfMatchPattern(lpInsn) == false) {
                        continue;
                    }

                    if (CheckIfFound(lpInsn, KeywordIndex) == false) {
                        throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Missing a patch."));
                    }

                    Patch[KeywordIndex] = CreatePatchPoint(Disassembler.GetInstructionContext().lpMachineCode, lpInsn, KeywordIndex);

                    ++KeywordIndex;
                }

                if (KeywordIndex == _countof(Patch)) {
                    break;
                }
            }

            if (KeywordIndex != _countof(Patch)) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Some patches are not found."));
            }

            LOG_SUCCESS(0, "PatchSolution3 ...... Ready to apply");
            for (size_t i = 0; i < _countof(Patch); ++i) {
                _Patch[i] = Patch[i];
                LOG_HINT(4, "[%3zu] Instruction RVA = 0x%.8llx, Patch Offset = +0x%.8zx", i, _Patch[i].OpcodeRva, address_delta(_Patch[i].lpPatch, _Image.ImageBase()));
            }

            return true;
        } catch (nkg::Exception&) {
            memset(_Patch, 0, sizeof(_Patch));

            LOG_FAILURE(0, "PatchSolution3 ...... Omitted");

            return false;
        }
    }
}

