#include "PatchSolutions.hpp"
#include "ExceptionGeneric.hpp"
#include "Misc.hpp"
#include <string.h>

namespace nkg {

    PatchSolution0::PatchSolution0(const Elf64Interpreter& Image) :
        m_Image(Image),
        m_DisassemblyEngine(CS_ARCH_X86, CS_MODE_64),
        m_AssemblyEngine(KS_ARCH_X86, KS_MODE_64),
        m_RefSegment(nullptr) 
    {
        m_DisassemblyEngine.Option(CS_OPT_DETAIL, CS_OPT_ON);
    }

    [[nodiscard]]
    bool PatchSolution0::FindPatchOffset() noexcept {
        try {
            const Elf64_Phdr* RefSegment = nullptr;
            std::optional<Elf64_Off>    PatchMarkOffset;
            std::optional<Elf64_Addr>   PatchMarkRva;
            std::optional<Elf64_Addr>   MachineCodeRva;
            std::optional<size_t>       MachineCodeSize;
            std::vector<uint8_t>        MachineCodeNew;

            if (m_Image.ElfHeader()->e_machine != EM_X86_64) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "Not amd64 platform.");
            }

            for (size_t i = 0; i < m_Image.NumberOfElfProgramHeaders(); ++i) {
                auto seg_hdr = m_Image.ElfProgramHeader(i);
                if (seg_hdr->p_type != PT_NULL && seg_hdr->p_filesz >= sizeof(PatchMarkType)) {
                    auto lpMark = m_Image.ElfOffset<const PatchMarkType*>(seg_hdr->p_offset + seg_hdr->p_filesz - sizeof(PatchMarkType));
                    if (lpMark->Starter == PatchMarkStarter || lpMark->Terminator == PatchMarkTerminator) {
                        throw ARL::Exception(__BASE_FILE__, __LINE__, "Already patched.");
                    }
                }
            }

            {
                std::map<Elf64_Off, Elf64_Xword> SpaceMap{ { 0, m_Image.ElfSize() } };
                
                SearchFreeSpace(SpaceMap, m_Image);
                
                for (const auto& space : SpaceMap) {
                    bool found = false;
                    auto offset = space.first;
                    auto size = space.second;
                    
                    if (size >= sizeof(PatchMarkType)) {
                        for (size_t i = 0; i < m_Image.NumberOfElfProgramHeaders(); ++i) {
                            auto seg_hdr = m_Image.ElfProgramHeader(i);
                            if (seg_hdr->p_type == PT_LOAD && seg_hdr->p_offset + seg_hdr->p_filesz == offset) {
                                RefSegment = seg_hdr;
                                PatchMarkOffset = offset;
                                PatchMarkRva = m_Image.ConvertOffsetToRva(offset - 1) + 1;
                                found = true;
                                break;
                            }
                        }
                    }

                    if (found) {
                        break;
                    }
                }
            }

            {
                auto Disassembler = m_DisassemblyEngine.CreateDisassembler();
                auto Assembler = m_AssemblyEngine.CreateAssembler();

                auto sec_hdr_text = m_Image.ElfSectionHeader(".text");
                auto sec_view_text = m_Image.ElfSectionView(sec_hdr_text);
                auto lpMachineCode = m_Image.SearchElfSectionView(sec_hdr_text, [](const void* base, size_t i, size_t size) {
                        auto p = reinterpret_cast<const uint8_t*>(base) + i;
                        return i + 16 <= size &&
                            p[1] == 0x0f && p[2] == 0xb6 &&     // movzx xxx, yyy
                            p[6] == 0x8b &&                     // mov xxx, yyy
                            p[10] == 0x8b &&                    // mov xxx, yyy
                            p[13] == 0x85 &&                    // test xxx, yyy
                            p[15] == 0x79;                      // jns xxx
                    }
                );
                auto cbMachineCode = static_cast<size_t>(sec_hdr_text->sh_size - ARL::AddressDelta(lpMachineCode, sec_view_text));
                MachineCodeRva = m_Image.ConvertPtrToRva(lpMachineCode);
                
                Disassembler.SetContext({ lpMachineCode, cbMachineCode, MachineCodeRva.value() });

                int char_reg;
                int lpsz_reg;
                if (Disassembler.Next() && strcasecmp(Disassembler.GetInstruction()->mnemonic, "movzx") == 0) {
                    auto lpInsn = Disassembler.GetInstruction();
                    if (lpInsn->detail->x86.operands[0].type == X86_OP_REG) {
                        char_reg = lpInsn->detail->x86.operands[0].reg;
                    } else {
                        throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Something unexpected happened.");
                    }
                } else {
                    throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Something unexpected happened.");
                }

                if (Disassembler.Next() && strcasecmp(Disassembler.GetInstruction()->mnemonic, "mov") == 0) {
                    auto lpInsn = Disassembler.GetInstruction();
                    if (lpInsn->detail->x86.operands[0].type == X86_OP_REG) {
                        lpsz_reg = lpInsn->detail->x86.operands[0].reg;
                    } else {
                        throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Something unexpected happened.");
                    }
                } else {
                    throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Something unexpected happened.");
                }

                if (Disassembler.Next() && Disassembler.Next() && Disassembler.Next()) {
                    MachineCodeSize = static_cast<size_t>(Disassembler.GetContext().Address - MachineCodeRva.value());
                    MachineCodeNew = Assembler.GenerateMachineCode(
                        [this, char_reg, lpsz_reg, &PatchMarkRva]() -> std::string {
                            const char asm_template[] = 
                                "xor %1$s, %1$s;"
                                "lea %2$s, byte ptr [0x%3$.16lx];";
                            std::string asm_string;
                            int l;
                
                            l = snprintf(nullptr, 0, 
                                asm_template, 
                                this->m_DisassemblyEngine.GetRegisterName(char_reg), 
                                this->m_DisassemblyEngine.GetRegisterName(lpsz_reg),
                                PatchMarkRva.value() + offsetof(PatchMarkType, Data)
                            );
                            if (l < 0) {
                                std::terminate();
                            }

                            asm_string.resize(l + 1);

                            l = snprintf(asm_string.data(), asm_string.length(), 
                                asm_template, 
                                this->m_DisassemblyEngine.GetRegisterName(char_reg), 
                                this->m_DisassemblyEngine.GetRegisterName(lpsz_reg),
                                PatchMarkRva.value() + offsetof(PatchMarkType, Data)
                            );
                            if (l < 0) {
                                std::terminate();
                            }

                            while (asm_string.back() == '\x00') {
                                asm_string.pop_back();
                            }

                            return asm_string;
                        }().c_str(),
                        MachineCodeRva.value()
                    );

                    if (MachineCodeNew.size() <= MachineCodeSize.value()) {
                        MachineCodeNew.insert(MachineCodeNew.end(), MachineCodeSize.value() - MachineCodeNew.size(), '\x90');   // \x90 -> nop
                    } else {
                        throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Something unexpected happened.");
                    }
                } else {
                    throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Something unexpected happened.");
                }
            }

            if (RefSegment && PatchMarkOffset.has_value() && MachineCodeRva.has_value() && MachineCodeSize.has_value()) {
                m_RefSegment = RefSegment;
                m_PatchMarkOffset = PatchMarkOffset;
                m_MachineCodeRva = MachineCodeRva;
                m_MachineCodeSize = MachineCodeSize;
                m_MachineCodeNew = std::move(MachineCodeNew);

                printf("[+] PatchSolution0 ...... Ready to apply\n");
                printf("    RefSegment      =  %zu\n", m_RefSegment - m_Image.ElfProgramHeader(0));
                printf("    MachineCodeRva  =  0x%.16lx\n", m_MachineCodeRva.value());
                printf("    PatchMarkOffset = +0x%.16lx\n", PatchMarkOffset.value());
            } else {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "Not found.");
            }

            return true;
        } catch (ARL::Exception& e) {
            printf("[-] PatchSolution0 ...... Omitted\n");
            return false;
        }
    }

    [[nodiscard]]
    bool PatchSolution0::CheckKey(const RSACipher& Cipher) const noexcept {
        return Cipher.Bits() == 2048;
    }

    void PatchSolution0::MakePatch(const RSACipher& Cipher) const {
        if (m_RefSegment && m_PatchMarkOffset.has_value() && m_MachineCodeRva.has_value() && m_MachineCodeSize.has_value()) {
            if (m_MachineCodeSize.value() == m_MachineCodeNew.size()) {
                auto szPublicKey = Cipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

                for (auto pos = szPublicKey.find("-----BEGIN PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKey.find("-----BEGIN PUBLIC KEY-----", pos)) {
                    szPublicKey.erase(pos, strlen("-----BEGIN PUBLIC KEY-----"));
                }

                for (auto pos = szPublicKey.find("-----END PUBLIC KEY-----"); pos != std::string::npos; pos = szPublicKey.find("-----END PUBLIC KEY-----", pos)) {
                    szPublicKey.erase(pos, strlen("-----END PUBLIC KEY-----"));
                }

                for (auto pos = szPublicKey.find("\n"); pos != std::string::npos; pos = szPublicKey.find("\n", pos)) {
                    szPublicKey.erase(pos, strlen("\n"));
                }

                auto lpMark = m_Image.ElfOffset<PatchMarkType*>(m_PatchMarkOffset.value());

                puts("*******************************************************");
                puts("*                   PatchSolution0                    *");
                puts("*******************************************************");

                if (lpMark->Starter != PatchMarkStarter || lpMark->Terminator != PatchMarkTerminator) {
                    auto RefSegment = const_cast<Elf64_Phdr*>(m_RefSegment);

                    printf("[*] Previous:\n");
                    Misc::PrintMemory(RefSegment, sizeof(Elf64_Phdr), m_Image.ElfBase());
                        RefSegment->p_filesz += sizeof(PatchMarkType);
                        RefSegment->p_memsz += sizeof(PatchMarkType);
                    printf("[*] After:\n");
                    Misc::PrintMemory(RefSegment, sizeof(Elf64_Phdr), m_Image.ElfBase());
                    printf("\n");

                    printf("[*] Previous:\n");
                    Misc::PrintMemory(lpMark, sizeof(PatchMarkType), m_Image.ElfBase());
                        lpMark->Starter = PatchMarkStarter;
                        memcpy(lpMark->Data, szPublicKey.data(), std::min(szPublicKey.size(), sizeof(lpMark->Data)));
                        lpMark->Terminator = PatchMarkTerminator;
                    printf("[*] After:\n");
                    Misc::PrintMemory(lpMark, sizeof(PatchMarkType), m_Image.ElfBase());
                    printf("\n");
                } else {
                    if (strncmp(reinterpret_cast<char*>(lpMark->Data), szPublicKey.data(), sizeof(lpMark->Data)) != 0) {
                        printf("[*] Previous:\n");
                        Misc::PrintMemory(lpMark, sizeof(PatchMarkType), m_Image.ElfBase());
                            memcpy(lpMark->Data, szPublicKey.data(), std::min(szPublicKey.size(), sizeof(lpMark->Data)));
                        printf("[*] After:\n");
                        Misc::PrintMemory(lpMark, sizeof(PatchMarkType), m_Image.ElfBase());
                        printf("\n");
                    }
                }

                {
                    auto lpMachineCode = m_Image.ConvertRvaToPtr(m_MachineCodeRva.value());
                    printf("[*] Previous:\n");
                    Misc::PrintMemory(lpMachineCode, m_MachineCodeSize.value(), m_Image.ElfBase());
                        memcpy(lpMachineCode, m_MachineCodeNew.data(), m_MachineCodeSize.value());
                    printf("[*] After:\n");
                    Misc::PrintMemory(lpMachineCode, m_MachineCodeSize.value(), m_Image.ElfBase());
                    printf("\n");
                }
            } else {
                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Something unexpected happened.");
            }
        } else {
            throw ARL::Exception(__BASE_FILE__, __LINE__, "Not ready yet.");
        }
    }
}

