#include "PatchSolutions.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\PatchSolution3-generic.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    const PatchSolution3::KeywordInfo PatchSolution3::Keyword[111] = {
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
        { { 0x42 }, 1, IMM_DATA, false }
    };

    [[nodiscard]]
    bool PatchSolution3::IsPrintable(const void* p, size_t s) noexcept {
        auto pb = reinterpret_cast<const uint8_t*>(p);
        for (size_t i = 0; i < s; ++i) {
            if (isprint(pb[i]) == false) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]]
    CapstoneContext PatchSolution3::GetJumpedBranch(const CapstoneContext& NotJumpedBranch, const cs_insn* lpJxxInsn) const {
        CapstoneContext JumpedBranch;

        JumpedBranch.lpMachineCode = _Image.RvaToPointer<const void*>(
            static_cast<uintptr_t>(lpJxxInsn->detail->x86.operands[0].imm)
        );

        JumpedBranch.cbMachineCode = NotJumpedBranch.cbMachineCode - (
            reinterpret_cast<const uint8_t*>(JumpedBranch.lpMachineCode) - 
            reinterpret_cast<const uint8_t*>(NotJumpedBranch.lpMachineCode)
        );

        JumpedBranch.Address = lpJxxInsn->detail->x86.operands[0].imm;

        return JumpedBranch;
    }

    [[nodiscard]]
    CapstoneContext PatchSolution3::SelectBranch(const CapstoneContext& NotJumpedBranch, const CapstoneContext& JumpedBranch, size_t KeywordIdx) const {
        CapstoneContext A = NotJumpedBranch;
        CapstoneContext B = JumpedBranch;
        int WeightA = 0;
        int WeightB = 0;
        auto Disassembler = _Engine.CreateDisassembler();

        while (true) {
            int WeightAPrev = WeightA;
            int WeightBPrev = WeightB;

            //
            // process NotJumpedBranch
            //
            Disassembler.SetContext(A);
            while (Disassembler.Next()) {
                auto lpInsn = Disassembler.GetInstruction();

                //
                // For all x86 mnemonics, only 'jcc' or 'jmp' starts with 'j' or 'J'.
                // So it should be a new branch if we meet them.
                //
                if (lpInsn->mnemonic[0] == 'j' || lpInsn->mnemonic[0] == 'J') {
                    auto JumpedBranch = GetJumpedBranch(Disassembler.GetContext(), lpInsn);

                    if (_stricmp(lpInsn->mnemonic, "jmp") == 0) {
                        Disassembler.SetContext(JumpedBranch);
                    } else {
                        try {
                            Disassembler.SetContext(SelectBranch(Disassembler.GetContext(), JumpedBranch, KeywordIdx));
                        } catch (nkg::Exception&) {
                            // If exception occurs, give up NotJumpedBranch
                            break;
                        }
                    }
                } else if (_stricmp(lpInsn->mnemonic, "ret") == 0) {
                    return JumpedBranch;
                } else {
                    if (CheckIfMatchPattern(lpInsn) == false) {
                        continue;
                    }

                    //
                    // if match pattern, but keyword doesn't match, 
                    // NotJumpedBranch must not be what we want
                    //
                    if (CheckIfFound(lpInsn, KeywordIdx) == false) {
                        return JumpedBranch;
                    }

                    //
                    // If keyword is succeeded to match
                    // Add WeightA and stop processing NotJumpedBranch
                    //
                    ++WeightA;
                    break;
                }
            }
            A = Disassembler.GetContext();

            //
            // process JumpedBranch
            //
            Disassembler.SetContext(B);
            while (Disassembler.Next()) {
                auto lpInsn = Disassembler.GetInstruction();

                //
                // For all x86 mnemonics, only 'jcc' or 'jmp' starts with 'j' or 'J'.
                // So it should be a new branch if we meet them.
                //
                if (lpInsn->mnemonic[0] == 'j' || lpInsn->mnemonic[0] == 'J') {
                    auto JumpedBranch = GetJumpedBranch(Disassembler.GetContext(), lpInsn);

                    if (_stricmp(lpInsn->mnemonic, "jmp") == 0) {
                        Disassembler.SetContext(JumpedBranch);
                    } else {
                        try {
                            Disassembler.SetContext(SelectBranch(Disassembler.GetContext(), JumpedBranch, KeywordIdx));
                        } catch (nkg::Exception&) {
                            // If exception occurs, give up JumpedBranch
                            break;
                        }
                    }
                } else if (_stricmp(lpInsn->mnemonic, "ret") == 0) {
                    return NotJumpedBranch;
                } else {
                    if (CheckIfMatchPattern(lpInsn) == false) {
                        continue;
                    }

                    //
                    // if match pattern, but keyword doesn't match, 
                    // JumpedBranch must not be what we want
                    //
                    if (CheckIfFound(lpInsn, KeywordIdx) == false) {
                        return NotJumpedBranch;
                    }

                    //
                    // If keyword is succeeded to match
                    // Add WeightB and stop processing JumpedBranch
                    //
                    ++WeightB;
                    break;
                }
            }
            B = Disassembler.GetContext();

            //
            // If this happens, it means neither of two branch is our target
            if (WeightAPrev == WeightA && WeightBPrev == WeightB) {
                throw nkg::Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Branch is not selected."));
            }

            if (WeightA != WeightB)
                return WeightA > WeightB ? NotJumpedBranch : JumpedBranch;
            else
                ++KeywordIdx;
        }
    }

    [[nodiscard]]
    bool PatchSolution3::CheckKey(const RSACipher& Cipher) const noexcept {
        //
        // Brute-force search, cchString should be 1 or 2
        //
        auto SearchString = [](const void* lpRange, size_t cbRange, const char* lpString, size_t cchString) -> const char* {
            const char* p = reinterpret_cast<const char*>(lpRange);

            for (size_t i = 0; i < cbRange; ++i) {
                if (p[i] == lpString[0]) {
                    bool match = true;

                    __try {
                        for (size_t j = 1; j < cchString; ++j) {
                            if (p[i + j] != lpString[j]) {
                                match = false;
                                break;
                            }
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        match = false;
                    }

                    if (match && p[i + cchString] == '\x00')
                        return address_offset_cast<const char*>(lpRange, i);
                }
            }

            return nullptr;
        };

        auto szPublicKey = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

        for (auto pos = szPublicKey.find("-----BEGIN PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKey.find("-----BEGIN PUBLIC KEY-----", pos)) {
            szPublicKey.erase(pos, literal_length("-----BEGIN PUBLIC KEY-----"));
        }

        for (auto pos = szPublicKey.find("-----END PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKey.find("-----END PUBLIC KEY-----", pos)) {
            szPublicKey.erase(pos, literal_length("-----END PUBLIC KEY-----"));
        }

        for (auto pos = szPublicKey.find("\n"); pos != std::string::npos; pos = szPublicKey.find("\n", pos)) {
            szPublicKey.erase(pos, literal_length("\n"));
        }

        if (szPublicKey.length() != 0x188) {
            return false;
        }

        size_t PublicKeyReadCursor = 0;
        auto SectionHeader_rdata = _Image.ImageSectionHeader(".rdata");
        auto SectionView_rdata = _Image.ImageSectionView(SectionHeader_rdata);
        
        for (size_t i = 0; i < _countof(_Patch); PublicKeyReadCursor += Keyword[i].Size, ++i) {
            if (Keyword[i].NotRecommendedToModify) {
                _Patch[i].lpReplaceString = nullptr;

                const char* lpReplaceString = nullptr;
                const void* lpSearchRange = _Patch[i].lpOriginalString;
                size_t      cbSearchRange = SectionHeader_rdata->SizeOfRawData - address_delta(_Patch[i].lpOriginalString, SectionView_rdata);

                for (size_t offset = 0;;) {
                    lpReplaceString = SearchString(
                        address_offset(lpSearchRange, offset),
                        cbSearchRange - offset,
                        szPublicKey.c_str() + PublicKeyReadCursor,
                        Keyword[i].Size
                    );

                    if (lpReplaceString == nullptr) {
                        return false;
                    }

                    if (_Image.IsRvaRangeInRelocTable(_Image.PointerToRva(lpReplaceString), Keyword[i].Size + 1)) {
                        //
                        // Damn it!
                        // ReplaceString will be modified during relocation
                        // We have to find another one
                        //
                        ++offset;
                    } else {
                        //
                        // ReplaceString won't be modified during relocation
                        //   which can be used to act as a part of public key string
                        //
                        break;
                    }
                }

                _Patch[i].lpReplaceString = const_cast<char*>(lpReplaceString);
            }
        }

        return true;
    }

    void PatchSolution3::MakePatch(const RSACipher& Cipher) const {
        for (size_t i = 0; i < _countof(_Patch); ++i) {
            if (_Patch[i].lpPatch == nullptr) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PatchSolution3 has not been ready yet."));
            }
        }

        auto szPublicKey = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

        for (auto pos = szPublicKey.find("-----BEGIN PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKey.find("-----BEGIN PUBLIC KEY-----", pos)) {
            szPublicKey.erase(pos, literal_length("-----BEGIN PUBLIC KEY-----"));
        }

        for (auto pos = szPublicKey.find("-----END PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKey.find("-----END PUBLIC KEY-----", pos)) {
            szPublicKey.erase(pos, literal_length("-----END PUBLIC KEY-----"));
        }

        for (auto pos = szPublicKey.find("\n"); pos != std::string::npos; pos = szPublicKey.find("\n", pos)) {
            szPublicKey.erase(pos, literal_length("\n"));
        }

        _putts(TEXT("*******************************************************"));
        _putts(TEXT("*                   PatchSolution3                    *"));
        _putts(TEXT("*******************************************************"));

        size_t readptr = 0;
        for (size_t i = 0; i < _countof(_Patch); readptr += Keyword[i].Size, ++i) {
            _tprintf_s(TEXT("[*] +%.8zx: "), address_delta(_Patch[i].lpPatch, _Image.ImageBase()));

            PrintBytes(_Patch[i].lpPatch, _Patch[i].cbPatch);
            _tprintf_s(TEXT(" ---> "));

            if (Keyword[i].NotRecommendedToModify) {
                auto offset = _Patch[i].lpReplaceString - _Patch[i].lpOriginalString;
                uint64_t disp = 0;

                memcpy(&disp, _Patch[i].lpPatch, _Patch[i].cbPatch);
                disp += offset;

                memcpy(_Patch[i].lpPatch, &disp, _Patch[i].cbPatch);
            } else {
                memcpy(_Patch[i].lpPatch, szPublicKey.c_str() + readptr, Keyword[i].Size);
            }

            PrintBytes(_Patch[i].lpPatch, _Patch[i].cbPatch);
            _tprintf_s(TEXT("\n"));
        }

        _putts(TEXT(""));
        return;
    }
}

