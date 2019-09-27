#include "PatchSolutions.hpp"
#include <xstring.hpp>

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\PatchSolution4-i386.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    PatchSolution4::PatchSolution4(const ImageInterpreter& Image) :
        _Image(Image),
        _DisassemblyEngine(CS_ARCH_X86, CS_MODE_32),
        _AssemblyEngine(KS_ARCH_X86, KS_MODE_32),
        _pbPatchMachineCode(nullptr),
        _pbPatchNewPublicKey(nullptr) { _DisassemblyEngine.Option(CS_OPT_DETAIL, CS_OPT_ON); }

    PatchSolution4::PatchSolution4(const ImageInterpreter* Image) :
        _Image(*Image),
        _DisassemblyEngine(CS_ARCH_X86, CS_MODE_32),
        _AssemblyEngine(KS_ARCH_X86, KS_MODE_32),
        _pbPatchMachineCode(nullptr),
        _pbPatchNewPublicKey(nullptr) { _DisassemblyEngine.Option(CS_OPT_DETAIL, CS_OPT_ON); }

    bool PatchSolution4::FindPatchOffset() noexcept {
        try {
            _pbPatchMachineCode = _Image.SearchSection<uint8_t*>(".text", [](const uint8_t* p) {
                __try {
                    return
                        p[0] == 0x83 &&                     // prefix of "cmp     [ebp+var_30], 10h"
                        p[4] == 0x8d &&                     // prefix of "lea     ecx, [ebp+Dst]"
                        p[7] == 0x8d &&                     // prefix of "lea     eax, [ebp+Memory]"
                        p[10] == 0x0f && p[11] == 0x43 &&   // prefix of "cmovnb  ecx, [ebp+Dst]"
                        p[14] == 0x83 &&                    // prefix of "cmp     [ebp+var_18], 10h"
                        p[18] == 0x0f && p[19] == 0x43 &&   // prefix of "cmovnb  eax, [ebp+Memory]"
                        p[22] == 0x8a &&                    // prefix of "mov     dl, [eax+ebx]"
                        p[25] == 0x02;                      // prefix of "add     dl, [ecx+ebx]"
                    //  p[28]
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            });

            auto RegisterIndex = X86_REG_INVALID;
            auto RegisterFinalValue = X86_REG_INVALID;
            auto Disassembler = _DisassemblyEngine.CreateDisassembler();
            Disassembler.SetContext({ _pbPatchMachineCode, 28, _Image.PointerToVa(_pbPatchMachineCode) });

            if (Disassembler.Next() && Disassembler.Next() && Disassembler.Next() && Disassembler.Next() && Disassembler.Next() && Disassembler.Next() && Disassembler.Next()) {
                auto lpInsn = Disassembler.GetInstruction();
                if (_stricmp(lpInsn->mnemonic, "mov") == 0 && 
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

            if (Disassembler.Next()) {
                auto lpInsn = Disassembler.GetInstruction();
                if (_stricmp(lpInsn->mnemonic, "add") == 0 && 
                    lpInsn->detail->x86.op_count >= 1 &&
                    lpInsn->detail->x86.operands[0].type == X86_OP_REG &&
                    lpInsn->detail->x86.operands[0].size == 1) 
                {
                    RegisterFinalValue = lpInsn->detail->x86.operands[0].reg;
                } else {
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
                                    "call +5;"
                                    "pop eax;"
                                    "add eax, 0x%.8x;"
                                    "mov %hs, byte ptr [eax + %hs];"
                                ),
                                _Image.PointerToVa(_pbPatchNewPublicKey) - (_Image.PointerToVa(_pbPatchMachineCode) + 5),
                                _DisassemblyEngine.GetRegisterName(RegisterFinalValue),
                                _DisassemblyEngine.GetRegisterName(RegisterIndex)
                            ).explicit_string().c_str()
                        );

                        // >>>>>>>>>>>> .text:113FE4A0 83 7D D0 10  cmp     [ebp+var_30], 10h
                        //   28 BYTES   .text:113FE4A4 8D 4D BC     lea     ecx, [ebp+Dst]
                        //              .text:113FE4A7 8D 45 D4     lea     eax, [ebp+Memory]
                        //  THESE CODE  .text:113FE4AA 0F 43 4D BC  cmovnb  ecx, [ebp+Dst]
                        //  WILL BE     .text:113FE4AE 83 7D E8 10  cmp     [ebp+var_18], 10h
                        //  REPLACED    .text:113FE4B2 0F 43 45 D4  cmovnb  eax, [ebp+Memory]
                        //              .text:113FE4B6 8A 14 18     mov     dl, [eax+ebx]
                        // <<<<<<<<<<<< .text:113FE4B9 02 14 19     add     dl, [ecx+ebx]
                        while (_NewMachineCode.size() < 28) {
                            _NewMachineCode.emplace_back(0x90);     // padding with "nop"
                        }

                        if (_NewMachineCode.size() != 28) {
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

