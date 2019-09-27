#include "PatchSolutions.hpp"
#include <xstring.hpp>

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\PatchSolution4-amd64.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    PatchSolution4::PatchSolution4(const ImageInterpreter& Image) :
        _Image(Image),
        _DisassemblyEngine(CS_ARCH_X86, CS_MODE_64),
        _AssemblyEngine(KS_ARCH_X86, KS_MODE_64),
        _pbPatchMachineCode(nullptr),
        _pbPatchNewPublicKey(nullptr) { _DisassemblyEngine.Option(CS_OPT_DETAIL, CS_OPT_ON); }

    PatchSolution4::PatchSolution4(const ImageInterpreter* Image) :
        _Image(*Image),
        _DisassemblyEngine(CS_ARCH_X86, CS_MODE_64),
        _AssemblyEngine(KS_ARCH_X86, KS_MODE_64),
        _pbPatchMachineCode(nullptr),
        _pbPatchNewPublicKey(nullptr) { _DisassemblyEngine.Option(CS_OPT_DETAIL, CS_OPT_ON); }

    bool PatchSolution4::FindPatchOffset() noexcept {
        try {
            _pbPatchMachineCode = _Image.SearchSection<uint8_t*>(".text", [](const uint8_t* p) {
                __try {
                    return
                        p[0] == 0x48 && p[1] == 0x8d &&                     // prefix of "lea       rcx, [rbp+5Fh+var_38]"
                        p[4] == 0x48 && p[5] == 0x83 &&                     // prefix of "cmp       [rbp+5Fh+var_20], 10h"
                        p[9] == 0x48 && p[10] == 0x0f && p[11] == 0x43 &&   // prefix of "cmovnb    rcx, [rbp+5Fh+var_38]"
                        p[14] == 0x48 && p[15] == 0x8d &&                   // prefix of "lea       rax, [rbp+5Fh+var_58]"
                        p[18] == 0x48 && p[19] == 0x83 &&                   // prefix of "cmp       [rbp+5Fh+var_40], 10h"
                        p[23] == 0x48 && p[24] == 0x0f && p[25] == 0x43 &&  // prefix of "cmovnb    rax, [rbp+5Fh+var_58]"
                        p[28] == 0x44 && p[29] == 0x0f && p[30] == 0xb6 &&  // prefix of "movzx     r8d, byte ptr [rax+rdi]"
                        p[33] == 0x44 && p[34] == 0x02 &&                   // prefix of "add       r8b, [rcx+rdi]"
                        p[37] == 0xba &&                                    // prefix of "mov       edx, 1"
                        p[42] == 0x48 && p[43] == 0x8b &&                   // prefix of "mov       rcx, rbx"
                        p[45] == 0xe8;                                      // prefix of "call      sub_1806E65F0"
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            });

            auto RegisterIndex = X86_REG_INVALID;
            auto Disassembler = _DisassemblyEngine.CreateDisassembler();
            Disassembler.SetContext({ _pbPatchMachineCode, 45, _Image.PointerToVa(_pbPatchMachineCode) });

            if (Disassembler.Next() && Disassembler.Next() && Disassembler.Next() && Disassembler.Next() && Disassembler.Next() && Disassembler.Next() && Disassembler.Next()) {
                auto lpInsn = Disassembler.GetInstruction();
                if (_stricmp(lpInsn->mnemonic, "movzx") == 0 && 
                    lpInsn->detail->x86.op_count == 2 &&
                    lpInsn->detail->x86.operands[0].type == X86_OP_REG &&
                    lpInsn->detail->x86.operands[1].type == X86_OP_MEM && 
                    lpInsn->detail->x86.operands[1].size == 1 &&
                    lpInsn->detail->x86.operands[1].mem.scale == 1) 
                {
                    RegisterIndex = lpInsn->detail->x86.operands[1].mem.index;
                } else {
                    throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Unexpected machine code."));
                }
            } else {
                throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Disassemble failed."));
            }

            if (Disassembler.Next() && Disassembler.Next() && Disassembler.Next()) {
                auto lpInsn = Disassembler.GetInstruction();

                //
                // The previous instruction of "call sub_1806E65F0" should set RCX register.
                //
                if (_stricmp(lpInsn->mnemonic, "mov") != 0 || 
                    lpInsn->detail->x86.op_count < 1 ||
                    lpInsn->detail->x86.operands[0].type != X86_OP_REG || 
                    lpInsn->detail->x86.operands[0].reg != X86_REG_RCX) 
                {
                    throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Unexpected machine code."));
                }
            } else {
                throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Disassemble failed."));
            }

            for (size_t i = 0; i < _Image.NumberOfSections(); ++i) {
                auto lpSectionHeader = _Image.ImageSectionHeader(i);
                if (lpSectionHeader->SizeOfRawData > lpSectionHeader->Misc.VirtualSize) {
                    auto cbReserved = 
                        lpSectionHeader->SizeOfRawData - 
                        lpSectionHeader->Misc.VirtualSize;

                    if (cbReserved >= 0x188) {
                        _pbPatchNewPublicKey = _Image.ImageSectionView<uint8_t*>(lpSectionHeader, lpSectionHeader->Misc.VirtualSize);

                        auto Assembler = _AssemblyEngine.CreateAssembler();
                        _NewMachineCode = Assembler.GenerateMachineCode(
                            std::xstring::format(
                                TEXT(
                                    "lea rax, qword ptr[0x%.16llx];"
                                    "mov r8b, byte ptr[rax + %hs];"
                                    "mov edx, 1;"
                                ),
                                _Image.PointerToVa(_pbPatchNewPublicKey),
                                _DisassemblyEngine.GetRegisterName(RegisterIndex)
                            ).explicit_string().c_str(),
                            _Image.PointerToVa(_pbPatchMachineCode)
                        );

                        // >>>>>>>>>>>> .text:00000001819B02C0 48 8D 4D 27       lea     rcx, [rbp + 5Fh + var_38]
                        //              .text:00000001819B02C4 48 83 7D 3F 10    cmp[rbp + 5Fh + var_20], 10h
                        //  42 BYTES    .text:00000001819B02C9 48 0F 43 4D 27    cmovnb  rcx, [rbp + 5Fh + var_38]
                        //              .text:00000001819B02CE 48 8D 45 07       lea     rax, [rbp + 5Fh + var_58]
                        //  THESE CODE  .text:00000001819B02D2 48 83 7D 1F 10    cmp[rbp + 5Fh + var_40], 10h
                        //  WILL BE     .text:00000001819B02D7 48 0F 43 45 07    cmovnb  rax, [rbp + 5Fh + var_58]
                        //  REPLACED    .text:00000001819B02DC 44 0F B6 04 38    movzx   r8d, byte ptr[rax + rdi]
                        //              .text:00000001819B02E1 44 02 04 39       add     r8b, [rcx + rdi]
                        // <<<<<<<<<<<< .text:00000001819B02E5 BA 01 00 00 00    mov     edx, 1
                        //              .text:00000001819B02EA 48 8B CB          mov     rcx, rbx
                        //              .text:00000001819B02ED E8 FE 62 D3 FE    call    sub_1806E65F0
                        while (_NewMachineCode.size() < 42) {
                            _NewMachineCode.emplace_back(0x90);  // padding with "nop"
                        }

                        if (_NewMachineCode.size() != 42) {
                            throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Something unexpected happens."));
                        }

                        LOG_SUCCESS(0, "PatchSolution4 ...... Ready to apply");
                        LOG_HINT(4, "Machine code patch VA  = 0x%zx", _Image.PointerToVa(_pbPatchMachineCode));
                        LOG_HINT(4, "New public key VA      = 0x%zx", _Image.PointerToVa(_pbPatchNewPublicKey));
                        LOG_HINT(4, "New public key offset  = 0x%zx", _Image.PointerToFileOffset(_pbPatchNewPublicKey));

                        return true;
                    }
                }
            }

            throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("No space to store public key."));
        } catch (nkg::Exception&) {
            _pbPatchMachineCode = nullptr;
            _pbPatchNewPublicKey = nullptr;
            _NewMachineCode.clear();

            LOG_FAILURE(0, "PatchSolution4 ...... Omitted");

            return false;
        }
    }

}

