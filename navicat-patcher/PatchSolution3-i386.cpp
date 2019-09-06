#include "PatchSolutions.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\PatchSolution3-i386.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    PatchSolution3::PatchSolution3(const ImageInterpreter& Image) :
        _Image(Image),
        _Engine(CS_ARCH_X86, CS_MODE_32),
        _Patch{} 
    {
        _Engine.Option(CS_OPT_DETAIL, CS_OPT_ON);
    }

    PatchSolution3::PatchSolution3(const ImageInterpreter* lpImage) :
        _Image(*lpImage),
        _Engine(CS_ARCH_X86, CS_MODE_32),
        _Patch{} 
    {
        _Engine.Option(CS_OPT_DETAIL, CS_OPT_ON);
    }

    [[nodiscard]]
    bool PatchSolution3::CheckIfMatchPattern(const cs_insn* lpInsn) const noexcept {
        // the instruction we're interested in has one of the following patterns:
        //  1. mov PTR [MEM], IMM   (IMM must consist of printable chars)               // for KeywordType::IMM_DATA
        //     except pattern "mov [ebp - 0x4], IMM"
        //  2. push IMM             (IMM must consist of printable chars)               // for KeywordType::IMM_DATA
        //  3. push offset MEM      (MEM must point to a non-empty printable string)    // for KeywordType::STRING_DATA                     
        //

        if (_stricmp(lpInsn->mnemonic, "mov") == 0) {
            // filter the case "mov [ebp - 0x4], IMM"
            // because IMM may consist of printable chars in that case, which will mislead us.
            //
            // Here I use "> -0x30" to intensify condition, instead of "== -0x4"
            if (lpInsn->detail->x86.operands[0].type == X86_OP_MEM &&
                lpInsn->detail->x86.operands[0].mem.base == X86_REG_EBP &&
                lpInsn->detail->x86.operands[0].mem.disp > -0x30) 
            {
                return false;
            }

            if (lpInsn->detail->x86.operands[1].type != X86_OP_IMM) {
                return false;
            }

            auto pbImmValue = lpInsn->bytes + lpInsn->detail->x86.encoding.imm_offset;
            auto cbImmValue = lpInsn->detail->x86.encoding.imm_size;

            // each bytes of imm must be printable;
            return IsPrintable(pbImmValue, cbImmValue);
        } else if (_stricmp(lpInsn->mnemonic, "push") == 0) {
            if (lpInsn->detail->x86.operands[0].type != X86_OP_IMM) {
                return false;
            }

            // test if match pattern 2
            auto pbImmValue = lpInsn->bytes + lpInsn->detail->x86.encoding.imm_offset;
            auto cbImmValue = lpInsn->detail->x86.encoding.imm_size;
            if (IsPrintable(pbImmValue, cbImmValue)) {
                return true;
            }

            // test if match pattern 3
            auto StringRva = static_cast<uintptr_t>(
                lpInsn->detail->x86.operands[0].imm - _Image.ImageNtHeaders()->OptionalHeader.ImageBase
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
        //  1. mov PTR [MEM], IMM   (IMM must consist of printable chars)               // for KeywordType::IMM_DATA
        //     except pattern "mov [ebp - 0x4], IMM"
        //  2. push IMM             (IMM must consist of printable chars)               // for KeywordType::IMM_DATA
        //  3. push offset MEM      (MEM must point to a non-empty printable string)    // for KeywordType::STRING_DATA                     
        //

        auto& op_count = lpInsn->detail->x86.op_count;
        auto& operands = lpInsn->detail->x86.operands;

        if (op_count < 1 || operands[op_count - 1].type != X86_OP_IMM) {
            return false;
        }

        if (Keyword[KeywordIdx].Type == IMM_DATA) {
            static_assert(sizeof(operands[op_count - 1].imm) == sizeof(Keyword[KeywordIdx].Value));
            return
                operands[op_count - 1].imm == *reinterpret_cast<const int64_t*>(Keyword[KeywordIdx].Value) &&
                lpInsn->detail->x86.encoding.imm_size == Keyword[KeywordIdx].Size;
        } else if (Keyword[KeywordIdx].Type == STRING_DATA) {
            auto StringRva = static_cast<uintptr_t>(
                operands[op_count - 1].imm - _Image.ImageNtHeaders()->OptionalHeader.ImageBase
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

        if (Keyword[KeywordIdx].Type == IMM_DATA) {
            NewPatch.lpPatch = address_offset(NewPatch.lpOpcode, lpInsn->detail->x86.encoding.imm_offset);
            NewPatch.cbPatch = lpInsn->detail->x86.encoding.imm_size;
            NewPatch.lpOriginalString = nullptr;
        } else {
            auto StringRva = static_cast<uintptr_t>(
                lpInsn->detail->x86.operands[0].imm - _Image.ImageNtHeaders()->OptionalHeader.ImageBase
            );

            NewPatch.lpOriginalString = _Image.RvaToPointer<char*>(StringRva);

            if (Keyword[KeywordIdx].NotRecommendedToModify) {
                NewPatch.lpPatch = address_offset(NewPatch.lpOpcode, lpInsn->detail->x86.encoding.imm_offset);
                NewPatch.cbPatch = lpInsn->detail->x86.encoding.imm_size;
            } else {
                NewPatch.lpPatch = reinterpret_cast<uint8_t*>(NewPatch.lpOriginalString);
                NewPatch.cbPatch = Keyword[KeywordIdx].Size;
            }
        }

        NewPatch.lpReplaceString = nullptr;

        return NewPatch;
    }

    [[nodiscard]]
    bool PatchSolution3::FindPatchOffset() noexcept {
        try {
            static const uint8_t HeaderOfTargetFunction[] = {
                0x55,           // push    ebp
                0x8B, 0xEC,     // mov     ebp, esp
                0x6A, 0xFF      // push    0xffffffff
            };

            PatchInfo Patch[_countof(_Patch)] = {};

            const uint8_t* lpTargetFunction = nullptr;
            auto lptargetFunctionHint = _Image.SearchSection<const uint8_t*>(".text", [&lpTargetFunction](const uint8_t* p) {
                __try {
                    if (*reinterpret_cast<const uint32_t*>(p) == 0x6b67424e) {
                        auto i = p - 0x1B0;
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

            Disassembler.SetContext(CapstoneContext{ lpTargetFunction, 0x9014, _Image.PointerToRva(lpTargetFunction) });

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
                    return false;
                } else {
                    if (CheckIfMatchPattern(lpInsn) == false) {
                        continue;
                    }

                    if (CheckIfFound(lpInsn, KeywordIndex) == false) {
                        return false;
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

