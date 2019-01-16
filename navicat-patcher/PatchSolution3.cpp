#include "PatchSolution.hpp"
#include <tchar.h>
#include "Helper.hpp"
#include "ImageHelper.hpp"
#include <assert.h>

#undef __BASE_FILE__
#define __BASE_FILE__ "PatchSolution.cpp"

// ----------- avoid link error caused by capstone_static.lib
#define stdin  (__acrt_iob_func(0))
#define stdout (__acrt_iob_func(1))
#define stderr (__acrt_iob_func(2))

FILE _iob[] = { *stdin, *stdout, *stderr };
extern "C" FILE * __cdecl __iob_func(void) { return _iob; }
// ------------

const PatchSolution3::KeywordType PatchSolution3::Keywords[KeywordsCount] = {
    { { 0x4d, 0x49, 0x49 }, 3, STRING_DATA, false },
    { { 0x42, 0x49 }, 2, IMM_DATA, false },
    { { 0x6a }, 1, IMM_DATA, false },
    { { 0x41 }, 1, IMM_DATA, false },
    { { 0x4e, 0x42, 0x67, 0x6b }, 4, IMM_DATA, false },
    { { 0x71 }, 1, IMM_DATA, false },
    { { 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77 }, 6, STRING_DATA, false },
    { { 0x30 }, 1, STRING_DATA, true },
    { { 0x42 }, 1, IMM_DATA, false },
    { { 0x41 }, 1, IMM_DATA, false },
    { { 0x51, 0x45, 0x46, 0x41, 0x41, 0x4f, 0x43 }, 7, STRING_DATA, false },
    { { 0x41, 0x51, 0x38, 0x41, 0x4d, 0x49 }, 6, STRING_DATA, false },
    { { 0x49, 0x42 }, 2, STRING_DATA, false },
    { { 0x43, 0x67, 0x4b, 0x43 }, 4, IMM_DATA, false },
    { { 0x41, 0x51 }, 2, STRING_DATA, false },
    { { 0x45, 0x41, 0x77, 0x31 }, 4, IMM_DATA, false },
    { { 0x64, 0x71, 0x46, 0x33 }, 4, IMM_DATA, false },
    { { 0x53 }, 1, STRING_DATA, true },
    { { 0x6b, 0x43, 0x61, 0x41, 0x41, 0x6d }, 6, STRING_DATA, false },
    { { 0x4d, 0x7a, 0x73, 0x38 }, 4, IMM_DATA, false },
    { { 0x38, 0x39, 0x49, 0x71 }, 4, IMM_DATA, false },
    { { 0x64 }, 1, IMM_DATA, false },
    { { 0x57 }, 1, IMM_DATA, false },
    { { 0x39, 0x4d, 0x32, 0x64 }, 4, IMM_DATA, false },
    { { 0x49, 0x64, 0x68 }, 3, STRING_DATA, false },
    { { 0x33, 0x6a }, 2, IMM_DATA, false },
    { { 0x47, 0x39, 0x79, 0x50 }, 4, IMM_DATA, false },
    { { 0x63, 0x6d }, 2, IMM_DATA, false },
    { { 0x4c }, 1, IMM_DATA, false },
    { { 0x6e, 0x6d, 0x4a }, 3, STRING_DATA, false },
    { { 0x69, 0x47, 0x70, 0x42, 0x46, 0x34, 0x45 }, 7, STRING_DATA, false },
    { { 0x39, 0x56, 0x48, 0x53, 0x4d, 0x47 }, 6, STRING_DATA, false },
    { { 0x65, 0x38, 0x6f, 0x50, 0x41, 0x79, 0x32, 0x6b }, 8, STRING_DATA, false },
    { { 0x4a, 0x44 }, 2, STRING_DATA, false },
    { { 0x6d, 0x64 }, 2, IMM_DATA, false },
    { { 0x4e, 0x74, 0x34 }, 3, STRING_DATA, false },
    { { 0x42, 0x63, 0x45, 0x79, 0x67, 0x76 }, 6, STRING_DATA, false },
    { { 0x73, 0x73, 0x45, 0x66, 0x67, 0x69 }, 6, STRING_DATA, false },
    { { 0x6e, 0x76, 0x61, 0x35, 0x74 }, 5, STRING_DATA, false },
    { { 0x35, 0x6a, 0x6d, 0x33, 0x35, 0x32 }, 6, STRING_DATA, false },
    { { 0x55, 0x41 }, 2, IMM_DATA, false },
    { { 0x6f, 0x44, 0x6f, 0x73 }, 4, IMM_DATA, false },
    { { 0x55, 0x4a }, 2, IMM_DATA, false },
    { { 0x6b, 0x54, 0x58, 0x47, 0x51 }, 5, STRING_DATA, false },
    { { 0x68, 0x70, 0x41, 0x57, 0x4d, 0x46 }, 6, STRING_DATA, false },
    { { 0x34, 0x66, 0x42, 0x6d, 0x42 }, 5, STRING_DATA, false },
    { { 0x70, 0x4f, 0x33, 0x45 }, 4, IMM_DATA, false },
    { { 0x65, 0x64 }, 2, IMM_DATA, false },
    { { 0x47 }, 1, IMM_DATA, false },
    { { 0x36, 0x32, 0x72, 0x4f, 0x73, 0x71 }, 6, STRING_DATA, false },
    { { 0x4d }, 1, IMM_DATA, false },
    { { 0x42, 0x67, 0x6d, 0x53 }, 4, STRING_DATA, false },
    { { 0x64 }, 1, IMM_DATA, false },
    { { 0x41, 0x79, 0x78, 0x43, 0x53 }, 5, STRING_DATA, false },
    { { 0x50 }, 1, IMM_DATA, false },
    { { 0x42, 0x52, 0x4a, 0x49, 0x4f }, 5, STRING_DATA, false },
    { { 0x46, 0x52, 0x30, 0x51, 0x67, 0x5a, 0x46, 0x62 }, 8, STRING_DATA, false },
    { { 0x52 }, 1, IMM_DATA, false },
    { { 0x6e, 0x55, 0x30, 0x66 }, 4, STRING_DATA, false },
    { { 0x72, 0x6a, 0x33, 0x34 }, 4, IMM_DATA, false },
    { { 0x66 }, 1, STRING_DATA, true },
    { { 0x69, 0x56, 0x6d, 0x67 }, 4, IMM_DATA, false },
    { { 0x59, 0x69, 0x4c, 0x75 }, 4, STRING_DATA, false },
    { { 0x5a, 0x53, 0x41, 0x6d }, 4, IMM_DATA, false },
    { { 0x49, 0x62 }, 2, IMM_DATA, false },
    { { 0x73 }, 1, IMM_DATA, false },
    { { 0x38, 0x5a, 0x78, 0x69 }, 4, IMM_DATA, false },
    { { 0x48 }, 1, IMM_DATA, false },
    { { 0x50, 0x64, 0x70, 0x31 }, 4, IMM_DATA, false },
    { { 0x6f, 0x44 }, 2, IMM_DATA, false },
    { { 0x34 }, 1, IMM_DATA, false },
    { { 0x74, 0x55, 0x70, 0x76, 0x73, 0x46 }, 6, STRING_DATA, false },
    { { 0x63, 0x69, 0x34, 0x51, 0x4a, 0x74 }, 6, STRING_DATA, false },
    { { 0x59, 0x4e, 0x6a, 0x4e, 0x6e, 0x47, 0x55 }, 7, STRING_DATA, false },
    { { 0x32, 0x57, 0x50, 0x48 }, 4, STRING_DATA, false },
    { { 0x36, 0x72, 0x76, 0x43, 0x68, 0x47, 0x6c }, 7, STRING_DATA, false },
    { { 0x31, 0x49, 0x52, 0x4b, 0x72, 0x78, 0x4d, 0x74 }, 8, STRING_DATA, false },
    { { 0x71, 0x4c, 0x69, 0x65, 0x6c }, 5, STRING_DATA, false },
    { { 0x73, 0x76, 0x61, 0x6a, 0x55, 0x6a, 0x79, 0x72 }, 8, STRING_DATA, false },
    { { 0x67 }, 1, STRING_DATA, true },
    { { 0x4f, 0x43, 0x36, 0x4e, 0x6d, 0x79, 0x6d, 0x59 }, 8, STRING_DATA, false },
    { { 0x4d }, 1, IMM_DATA, false },
    { { 0x76, 0x5a, 0x4e }, 3, STRING_DATA, false },
    { { 0x45, 0x52, 0x33, 0x68, 0x74 }, 5, STRING_DATA, false },
    { { 0x46 }, 1, IMM_DATA, false },
    { { 0x45, 0x74, 0x4c, 0x31 }, 4, STRING_DATA, false },
    { { 0x65, 0x51, 0x62, 0x43, 0x79 }, 5, STRING_DATA, false },
    { { 0x54, 0x66, 0x44, 0x6d, 0x74, 0x59, 0x79, 0x51 }, 8, STRING_DATA, false },
    { { 0x31, 0x57, 0x74, 0x34 }, 4, STRING_DATA, false },
    { { 0x4f }, 1, IMM_DATA, false },
    { { 0x74, 0x31, 0x32, 0x6c, 0x78, 0x66 }, 6, STRING_DATA, false },
    { { 0x30 }, 1, IMM_DATA, false },
    { { 0x77, 0x56, 0x49, 0x52, 0x35 }, 5, STRING_DATA, false },
    { { 0x6d }, 1, IMM_DATA, false },
    { { 0x63, 0x47, 0x4e, 0x37 }, 4, STRING_DATA, false },
    { { 0x58, 0x43, 0x58, 0x4a }, 4, STRING_DATA, false },
    { { 0x52, 0x48, 0x4f, 0x46 }, 4, IMM_DATA, false },
    { { 0x48, 0x53 }, 2, IMM_DATA, false },
    { { 0x66 }, 1, IMM_DATA, false },
    { { 0x31, 0x67, 0x7a, 0x58, 0x57 }, 5, STRING_DATA, false },
    { { 0x61 }, 1, IMM_DATA, false },
    { { 0x62 }, 1, IMM_DATA, false },
    { { 0x52, 0x53 }, 2, STRING_DATA, false },
    { { 0x76, 0x6d, 0x74, 0x31, 0x6e }, 5, STRING_DATA, false },
    { { 0x72, 0x6c }, 2, STRING_DATA, true },
    { { 0x37, 0x73, 0x57 }, 3, STRING_DATA, false },
    { { 0x36, 0x63, 0x6a }, 3, STRING_DATA, false },
    { { 0x78, 0x6c, 0x6a, 0x75, 0x75, 0x51, 0x61 }, 7, STRING_DATA, false },
    { { 0x77, 0x49, 0x44, 0x41 }, 4, STRING_DATA, false },
    { { 0x51, 0x41 }, 2, IMM_DATA, false },
    { { 0x42 }, 1, IMM_DATA, false },
};

PatchSolution3::PatchSolution3() {
    cs_err cs_status;
    csh cs_handle;
#if defined(_M_IX86)
    cs_status = cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle);
#else
    cs_status = cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle);
#endif
    if (cs_status != CS_ERR_OK)
        throw CapstoneError(__BASE_FILE__, __LINE__, cs_status, 
                            "cs_open fails.");

    cs_status = cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (cs_status != CS_ERR_OK)
        throw CapstoneError(__BASE_FILE__, __LINE__, cs_status,
                            "cs_option fails.");

    _CapstoneHandle.TakeHoldOf(cs_handle);
    _pTargetFile = nullptr;
    memset(_Patches, 0, sizeof(_Patches));
}

bool PatchSolution3::CheckIfMatchPattern(cs_insn* pInstruction) const {
    // the instruction we're interested in has one of the following patterns:
    //  1. mov PTR [MEM], IMM
    //  2. lea REG, PTR [MEM]
    //
    // They both have 2 operands.
    // So if op_count != 2, just pass and see the next one.
    if (pInstruction->detail->x86.op_count != 2)
        return false;

    if (pInstruction->detail->x86.operands[1].type == X86_OP_IMM) {
        uint64_t imm = pInstruction->detail->x86.operands[1].imm;
        uint8_t imm_size = pInstruction->detail->x86.operands[1].size;

        // check that each bytes of imm must be printable;
        for (uint8_t i = 0; i < imm_size; ++i) {
            uint8_t c = static_cast<uint8_t>(imm & 0xff);
            imm >>= 8;

            if (isprint(c) == false)
                return false;
        }

        return true;
    } else if (pInstruction->detail->x86.operands[1].type == X86_OP_MEM) {
        // as far as I know, all strings are loaded by "lea REG, QWORD PTR[RIP + disp]"
        if (_stricmp(pInstruction->mnemonic, "lea") != 0)
            return false;

        if (pInstruction->detail->x86.operands[1].mem.base != X86_REG_RIP)
            return false;

        // scale must 1, otherwise pattern mismatches
        if (pInstruction->detail->x86.operands[1].mem.scale != 1)
            return false;

        auto StringRva =
            pInstruction->address + pInstruction->size +    // RIP
            pInstruction->detail->x86.operands[1].mem.disp;

        auto pString = RvaToPointer<uint8_t*>(static_cast<SIZE_T>(StringRva),
                                              _pTargetFile->GetView<PVOID>());

        // If not found, pattern mismatches
        if (pString == nullptr)
            return false;

        // pString must have at least one char
        if (*pString == '\x00')
            return false;

        // every char in pString must be printable, otherwise pattern mismatches
        while (*pString != '\x00') {
            if (isprint(*pString) == false)
                return false;
            pString++;
        }

        return true;
    } else {
        return false;
    }
}

bool PatchSolution3::CheckIfFound(cs_insn* pInstruction, size_t KeywordIndex) const {
    if (pInstruction->detail->x86.op_count != 2)
        return false;

    if (pInstruction->detail->x86.operands[1].type == X86_OP_IMM) {
        uint64_t imm = pInstruction->detail->x86.operands[1].imm;
        return imm == *reinterpret_cast<const uint64_t*>(Keywords[KeywordIndex].data);
    } else if (pInstruction->detail->x86.operands[1].type == X86_OP_MEM) {
        auto StringRva =
            pInstruction->address + pInstruction->size +    // RIP
            pInstruction->detail->x86.operands[1].mem.disp;

        auto pString = RvaToPointer<char*>(static_cast<SIZE_T>(StringRva),
                                           _pTargetFile->GetView<PVOID>());
        if (pString == nullptr)
            return false;

        if (memcmp(pString, Keywords[KeywordIndex].data, Keywords[KeywordIndex].length) == 0 &&
            pString[Keywords[KeywordIndex].length] == '\x00')
            return true;

        return false;
    } else {
        return false;
    }
}

PatchSolution3::BranchType PatchSolution3::GetAnotherBranch(const BranchType& A, 
                                                        cs_insn* pInstruction) const {
    BranchType B;

    B.PtrOfCode = RvaToPointer<const uint8_t*>(
        static_cast<SIZE_T>(pInstruction->detail->x86.operands[0].imm),
        _pTargetFile->GetView<PVOID>()
        );
    assert(B.PtrOfCode != nullptr);

    B.SizeOfCode = A.SizeOfCode - (B.PtrOfCode - A.PtrOfCode);
    assert(static_cast<SSIZE_T>(B.SizeOfCode) >= 0);

    B.Rip = pInstruction->detail->x86.operands[0].imm;

    return B;
}

PatchSolution3::BranchType PatchSolution3::JudgeBranch(const BranchType A,
                                                   const BranchType B,
                                                   size_t CurrentKeywordIndex) const {
    BranchType CodeA = A;
    BranchType CodeB = B;
    int WeightA = 0;
    int WeightB = 0;
    ResourceGuard<CapstoneMallocTraits<cs_insn>> InstructionObj(cs_malloc(_CapstoneHandle));
    cs_insn* pInstruction = InstructionObj.GetHandle();

    if (InstructionObj.IsValid() == false)
        return { nullptr, 0, 0 };

    while (true) {
        // process branch A 
        while (cs_disasm_iter(_CapstoneHandle, &CodeA.PtrOfCode, &CodeA.SizeOfCode, &CodeA.Rip, pInstruction)) {
            // For all x86 mnemonics, only 'jcc' or 'jmp' starts with 'j' or 'J'.
            // So it should be a new branch if we meet them.
            if (pInstruction->mnemonic[0] == 'j' || pInstruction->mnemonic[0] == 'J') {
                if (_stricmp(pInstruction->mnemonic, "jmp") == 0) {
                    CodeA = GetAnotherBranch(CodeA, pInstruction);
                } else {
                    BranchType CodeC = GetAnotherBranch(CodeA, pInstruction);
                    CodeA = JudgeBranch(CodeA, CodeC, CurrentKeywordIndex);
                }

                if (CodeA.PtrOfCode == nullptr)
                    return { nullptr, 0, 0 };
            } else {
                if (!CheckIfMatchPattern(pInstruction))
                    continue;

                // if match pattern but keyword is failed to match, 
                // branch A must not be what we want
                if (CheckIfFound(pInstruction, CurrentKeywordIndex) == false)
                    return B;

                // If keyword is succeeded to match
                // Add WeightA and stop processing branch A
                WeightA++;
                break;
            }
        }

        // process B branch
        while (cs_disasm_iter(_CapstoneHandle, &CodeB.PtrOfCode, &CodeB.SizeOfCode, &CodeB.Rip, pInstruction)) {
            // For all x86 mnemonics, only 'jcc' or 'jmp' starts with 'j' or 'J'.
            // So it should be a new branch if we meet them.
            if (pInstruction->mnemonic[0] == 'j' || pInstruction->mnemonic[0] == 'J') {
                if (_stricmp(pInstruction->mnemonic, "jmp") == 0) {
                    CodeB = GetAnotherBranch(CodeB, pInstruction);
                } else {
                    BranchType CodeC = GetAnotherBranch(CodeB, pInstruction);
                    CodeB = JudgeBranch(CodeB, CodeC, CurrentKeywordIndex);
                }

                if (CodeB.PtrOfCode == nullptr)
                    return { nullptr, 0, 0 };
            } else {
                if (!CheckIfMatchPattern(pInstruction))
                    continue;

                if (CheckIfFound(pInstruction, CurrentKeywordIndex) == false)
                    return A;

                WeightB++;
                break;
            }
        }

        if (WeightA != WeightB) {
            return WeightA > WeightB ? A : B;
        }
    }
}

bool PatchSolution3::FindPatchOffset() noexcept {
    memset(_Patches, 0, sizeof(_Patches));

    uint8_t* pFileView = _pTargetFile->GetView<uint8_t>();
    PIMAGE_SECTION_HEADER pSectionHdrOftext = GetSectionHeaderByName(pFileView, ".text");
    PIMAGE_SECTION_HEADER pSectionHdrOfrdata = GetSectionHeaderByName(pFileView, ".rdata");
    uint8_t* pSectionOftext = pFileView + pSectionHdrOftext->PointerToRawData;
    uint8_t* pSectionOfrdata = pFileView + pSectionHdrOfrdata->PointerToRawData;
    off_t TargetFunctionOffset = -1;
    
    if (pSectionHdrOftext == nullptr)
        return false;

    if (pSectionHdrOfrdata == nullptr)
        return false;

    for (DWORD i = 0; i < pSectionHdrOftext->SizeOfRawData; ++i) {
        const uint32_t Hint = 0x6b67424e;
        if (*reinterpret_cast<uint32_t*>(pSectionOftext + i) == Hint) {

            static const uint8_t BeginBytesOfTargetFunction[] = {
                0x40, 0x55,                                         // push    rbp
                0x48, 0x8D, 0xAC, 0x24, 0x70, 0xBC, 0xFF, 0xFF,     // lea     rbp, [rsp-4390h]
                0xB8, 0x90, 0x44, 0x00, 0x00                        // mov     eax, 4490h
            };
            
            for (DWORD j = i - 0x250; j < i; ++j) {
                if (memcmp(pSectionOftext + j,
                           BeginBytesOfTargetFunction,
                           sizeof(BeginBytesOfTargetFunction)) == 0) {
                    TargetFunctionOffset = j;
                    break;
                }
            }

            break;
        }
    }

    if (TargetFunctionOffset == -1)
        return false;

    size_t KeywordIndex = 0;

#if defined(_M_X64)     // for x64 version
    {
        BranchType CurrentBranch;
        CurrentBranch.PtrOfCode = pSectionOftext + TargetFunctionOffset;
        CurrentBranch.SizeOfCode = 0xcd03;
        CurrentBranch.Rip = pSectionHdrOftext->VirtualAddress + TargetFunctionOffset;

        ResourceGuard<CapstoneMallocTraits<cs_insn>> InstructionObj(cs_malloc(_CapstoneHandle));
        cs_insn* pInstruction = InstructionObj.GetHandle();

        while (cs_disasm_iter(_CapstoneHandle, 
                              &CurrentBranch.PtrOfCode, 
                              &CurrentBranch.SizeOfCode, 
                              &CurrentBranch.Rip, pInstruction)) {

            if (pInstruction->mnemonic[0] == 'j' || pInstruction->mnemonic[0] == 'J') {
                if (_stricmp(pInstruction->mnemonic, "jmp") == 0) {
                    CurrentBranch = GetAnotherBranch(CurrentBranch, pInstruction);
                } else {
                    BranchType NewBranch = GetAnotherBranch(CurrentBranch, pInstruction);
                    CurrentBranch = JudgeBranch(CurrentBranch, NewBranch, KeywordIndex);
                }

                if (CurrentBranch.PtrOfCode == nullptr)
                    return false;
            } else {
                if (!CheckIfMatchPattern(pInstruction))
                    continue;

                if (!CheckIfFound(pInstruction, KeywordIndex))
                    return false;
                
                // record patches
                _Patches[KeywordIndex].PtrToRelativeCode = const_cast<uint8_t*>(CurrentBranch.PtrOfCode - pInstruction->size);
                _Patches[KeywordIndex].RelativeCodeRVA = pInstruction->address;
                if (pInstruction->detail->x86.operands[1].type == X86_OP_MEM) {
                    auto StringRva =
                        pInstruction->address + pInstruction->size +    // RIP
                        pInstruction->detail->x86.operands[1].mem.disp;

                    auto pString = RvaToPointer<char*>(static_cast<SIZE_T>(StringRva),
                                                       _pTargetFile->GetView<PVOID>());

                    _Patches[KeywordIndex].pOriginalString = pString;

                    if (Keywords[KeywordIndex].NotRecommendedToModify == false) {
                        _Patches[KeywordIndex].PtrToPatch = 
                            reinterpret_cast<uint8_t*>(_Patches[KeywordIndex].pOriginalString);
                        _Patches[KeywordIndex].PatchSize = 
                            Keywords[KeywordIndex].length;
                    } else {
                        _Patches[KeywordIndex].PtrToPatch =
                            _Patches[KeywordIndex].PtrToRelativeCode + pInstruction->detail->x86.encoding.disp_offset;
                        _Patches[KeywordIndex].PatchSize =
                            pInstruction->detail->x86.encoding.disp_size;
                    }
                } else {        // X86_OP_IMM
                    _Patches[KeywordIndex].PtrToPatch =
                        _Patches[KeywordIndex].PtrToRelativeCode + 
                        pInstruction->detail->x86.encoding.imm_offset;
                    _Patches[KeywordIndex].PatchSize = 
                        pInstruction->detail->x86.encoding.imm_size;
                    _Patches[KeywordIndex].pOriginalString = nullptr;
                }

                KeywordIndex++;
            }

            if (KeywordIndex == KeywordsCount)
                break;
        }
    }
#else       // for x86 version
#error "Not implement"
#endif
    
    if (KeywordIndex != KeywordsCount)
        return false;

    for (size_t i = 0; i < KeywordsCount; ++i) {
        _tprintf_s(TEXT("MESSAGE: [PatchSolution3] Keywords[%zu] has been found:\n"), i);
        _tprintf_s(TEXT("         Relative Machine Code Offset = +0x%016zx\n"), _Patches[i].PtrToRelativeCode - pFileView);
        _tprintf_s(TEXT("         Relative Machine Code RVA    = +0x%016llx\n"), _Patches[i].RelativeCodeRVA);
        _tprintf_s(TEXT("         Patch Offset                 = +0x%016zx\n"), _Patches[i].PtrToPatch - pFileView);
        _tprintf_s(TEXT("         Patch Size                   = %zu byte(s)\n"), _Patches[i].PatchSize);
    }

    return true;
}

// Brute-force search, str_s should be 1 or 2
static off_t SearchString(const void* p, size_t s, const char* str, size_t str_s) {
    const char* char_ptr = reinterpret_cast<const char*>(p);
    for (size_t i = 0; i < s; ++i) {
        if (char_ptr[i] == str[0]) {
            bool match = true;

            for (size_t j = 1; j < str_s; ++j) {
                if (char_ptr[i + j] != str[j]) {
                    match = false;
                    break;
                }
            }

            if (match && char_ptr[i + str_s] == '\x00')
                return static_cast<off_t>(i);
        }
    }
    return -1;
}

bool PatchSolution3::CheckKey(RSACipher* pCipher) const {
    std::string PublicKeyPem = pCipher->ExportKeyString<RSACipher::KeyType::PublicKey,
        RSACipher::KeyFormat::PEM>();

    PublicKeyPem.erase(PublicKeyPem.find("-----BEGIN PUBLIC KEY-----"), 26);
    PublicKeyPem.erase(PublicKeyPem.find("-----END PUBLIC KEY-----"), 24);
    {
        std::string::size_type pos = 0;
        while ((pos = PublicKeyPem.find("\n", pos)) != std::string::npos) {
            PublicKeyPem.erase(pos, 1);
        }
    }

    if(PublicKeyPem.length() != 0x188)
        return false;

    uint8_t* pFileView = _pTargetFile->GetView<uint8_t>();
    PIMAGE_NT_HEADERS pNtHeaders = GetImageNtHeaders(pFileView);
    PIMAGE_SECTION_HEADER pSectionHdrOfrdata = GetSectionHeaderByName(pFileView, ".rdata");
    uint8_t* pSectionOfrdata = pFileView + pSectionHdrOfrdata->PointerToRawData;

    size_t ptr = 0;
    for (size_t i = 0; i < KeywordsCount; ++i) {
        if (Keywords[i].NotRecommendedToModify) {
            auto offset = SearchString(_Patches[i].pOriginalString,
                                       pSectionHdrOfrdata->SizeOfRawData - (_Patches[i].pOriginalString - reinterpret_cast<char*>(pSectionOfrdata)),
                                       PublicKeyPem.data() + ptr,
                                       Keywords[i].length);
            if (offset == -1)
                return false;
            _Patches[i].pReplaceString = _Patches[i].pOriginalString + offset;
        }
        ptr += Keywords[i].length;
    }

    return true;
}

void PatchSolution3::MakePatch(RSACipher* pCipher) const {
    std::string PublicKeyPem = pCipher->ExportKeyString<RSACipher::KeyType::PublicKey,
        RSACipher::KeyFormat::PEM>();

    PublicKeyPem.erase(PublicKeyPem.find("-----BEGIN PUBLIC KEY-----"), 26);
    PublicKeyPem.erase(PublicKeyPem.find("-----END PUBLIC KEY-----"), 24);
    {
        std::string::size_type pos = 0;
        while ((pos = PublicKeyPem.find("\n", pos)) != std::string::npos) {
            PublicKeyPem.erase(pos, 1);
        }
    }

    uint8_t* pFileView = _pTargetFile->GetView<uint8_t>();

    size_t ptr = 0;
    for (size_t i = 0; i < KeywordsCount; ++i) {
        _tprintf_s(TEXT("@ +%08zx: "), _Patches[i].PtrToPatch - pFileView);
        Helper::PrintSomeBytes(_Patches[i].PtrToPatch, _Patches[i].PatchSize);

        _tprintf_s(TEXT(" -> "));
        if (Keywords[i].NotRecommendedToModify == false) {
            memcpy(_Patches[i].PtrToPatch, PublicKeyPem.data() + ptr, Keywords[i].length);
        } else {
            auto offset = _Patches[i].pReplaceString - _Patches[i].pOriginalString;

            union {
                uint8_t bytes[8];
                uint64_t qword;
            } disp = {};

            memcpy(disp.bytes, _Patches[i].PtrToPatch, _Patches[i].PatchSize);
            disp.qword += offset;
            memcpy(_Patches[i].PtrToPatch, disp.bytes, _Patches[i].PatchSize);
        }
        ptr += Keywords[i].length;

        Helper::PrintSomeBytes(_Patches[i].PtrToPatch, _Patches[i].PatchSize);
        _tprintf_s(TEXT("\n"));
    }
    return;
}



