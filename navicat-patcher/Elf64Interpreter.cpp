#include "Elf64Interpreter.hpp"
#include "Exception.hpp"
#include "ExceptionGeneric.hpp"
#include <memory.h>
#include <string.h>

namespace nkg {

    [[nodiscard]]
    Elf64Interpreter Elf64Interpreter::Parse(const void* lpImage, size_t cbImage) {
        Elf64Interpreter Interpreter;

        //
        // Checking ELF header
        //

        Interpreter.m_ElfSize = cbImage;
        Interpreter.m_lpElfHdr = reinterpret_cast<const Elf64_Ehdr*>(lpImage);
        if (ARL::AddressIsInRangeEx(Interpreter.m_lpElfHdr, sizeof(Elf64_Ehdr), lpImage, cbImage) == false) {
            throw ARL::Exception(__BASE_FILE__, __LINE__, "Bad ELF file: image is corrupted.");
        }

        if (memcmp(Interpreter.m_lpElfHdr->e_ident, ELFMAG, SELFMAG) != 0) {
            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: header magic check failure.");
        }

        if (Interpreter.m_lpElfHdr->e_ident[EI_CLASS] != ELFCLASS64) {
            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Unsupported ELF file: not ELF64 image.");
        }

        switch (Interpreter.m_lpElfHdr->e_ident[EI_DATA]) {
            case ELFDATA2LSB:
                if (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__) {
                    throw ARL::NotImplementedError(__BASE_FILE__, __LINE__, "Unsupported ELF file: unsupported endian.");
                }
                break;
            case ELFDATA2MSB:
                if (__BYTE_ORDER__ != __ORDER_BIG_ENDIAN__) {
                    throw ARL::NotImplementedError(__BASE_FILE__, __LINE__, "Unsupported ELF file: unsupported endian.");
                }
                break;
            default:
                throw ARL::Exception(__BASE_FILE__, __LINE__, "Bad ELF file: unknown endian.");
        }

        if (Interpreter.m_lpElfHdr->e_ident[EI_VERSION] != EV_CURRENT) {
            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Ehdr::e_ident[EI_VERSION] check failure.");
        }

        // Interpreter.m_lpElfHdr->e_ident[EI_OSABI]
        // Interpreter.m_lpElfHdr->e_ident[EI_ABIVERSION]

        for (int i = EI_PAD; i < sizeof(Interpreter.m_lpElfHdr->e_ident); ++i) {
            if (Interpreter.m_lpElfHdr->e_ident[i] != 0) {
                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Ehdr::e_ident padding contains non-zero byte(s).");
            }
        }

        if (Interpreter.m_lpElfHdr->e_version != EV_CURRENT) {
            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Ehdr::e_version check failure.");
        }

        if (Interpreter.m_lpElfHdr->e_ehsize != sizeof(Elf64_Ehdr)) {
            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Ehdr::e_ehsize check failure.");
        }

        if (Interpreter.m_lpElfHdr->e_phoff && Interpreter.m_lpElfHdr->e_phentsize && Interpreter.m_lpElfHdr->e_phnum) {
            if (Interpreter.m_lpElfHdr->e_phentsize != sizeof(Elf64_Phdr)) {
                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Ehdr::e_phentsize check failure.");
            }

            Interpreter.m_lpElfProgramHdr = 
                ARL::AddressOffsetWithCast<Elf64_Phdr*>(lpImage, Interpreter.m_lpElfHdr->e_phoff);

            auto a1 = Interpreter.m_lpElfProgramHdr;
            auto a2 = Interpreter.m_lpElfProgramHdr + Interpreter.m_lpElfHdr->e_phnum;
            if (a1 < a2) {
                if (ARL::AddressIsInRangeEx(a1, a2, lpImage, cbImage) == false) {
                    throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: image is corrupted.");
                }
            } else {
                throw ARL::OverflowError(__BASE_FILE__, __LINE__, "Bad ELF file: program header table overflowed.");
            }
        } else if (Interpreter.m_lpElfHdr->e_phoff == 0 && Interpreter.m_lpElfHdr->e_phentsize == 0 && Interpreter.m_lpElfHdr->e_phnum == 0) {
            Interpreter.m_lpElfProgramHdr = nullptr;
        } else {
            throw ARL::ValueError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Ehdr::e_ph* check failure.");
        }

        if (Interpreter.m_lpElfHdr->e_shoff && Interpreter.m_lpElfHdr->e_shentsize && Interpreter.m_lpElfHdr->e_shnum) {
            if (Interpreter.m_lpElfHdr->e_shentsize != sizeof(Elf64_Shdr)) {
                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Ehdr::e_shentsize check failure.");
            }

            Interpreter.m_lpElfSectionHdr = 
                ARL::AddressOffsetWithCast<Elf64_Shdr*>(lpImage, Interpreter.m_lpElfHdr->e_shoff);
            
            auto b1 = Interpreter.m_lpElfSectionHdr;
            auto b2 = Interpreter.m_lpElfSectionHdr + Interpreter.m_lpElfHdr->e_shnum;
            if (b1 < b2) {
                if (ARL::AddressIsInRangeEx(b1, b2, lpImage, cbImage) == false) {
                    throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: image is corrupted.");
                }
            } else {
                throw ARL::OverflowError(__BASE_FILE__, __LINE__, "Bad ELF file: section header table overflowed.");
            }
        } else if (Interpreter.m_lpElfHdr->e_shoff == 0 && Interpreter.m_lpElfHdr->e_shentsize == 0 && Interpreter.m_lpElfHdr->e_shnum == 0) {
            Interpreter.m_lpElfSectionHdr = nullptr;
        } else {
            throw ARL::ValueError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Ehdr::e_sh* check failure.");
        }

        if (Interpreter.m_lpElfHdr->e_shstrndx != SHN_UNDEF) {
            if (Interpreter.m_lpElfHdr->e_shstrndx >= Interpreter.m_lpElfHdr->e_shnum) {
                throw ARL::IndexError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Ehdr::e_shstrndx is out of range.");
            }
        }

        //
        // Checking program header table and section header table
        //

        if (Interpreter.m_lpElfProgramHdr && Interpreter.m_lpElfSectionHdr) {
            auto a1 = Interpreter.m_lpElfProgramHdr;
            auto a2 = Interpreter.m_lpElfProgramHdr + Interpreter.m_lpElfHdr->e_phnum;
            auto b1 = Interpreter.m_lpElfSectionHdr;
            auto b2 = Interpreter.m_lpElfSectionHdr + Interpreter.m_lpElfHdr->e_shnum;
            bool NotOverlapped = 
                (ARL::AddressDelta(a1, b1) < 0 && ARL::AddressDelta(a2, b1) <= 0) || 
                (ARL::AddressDelta(b1, a1) < 0 && ARL::AddressDelta(b2, a1) <= 0);
            if (NotOverlapped == false) {
                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: program header table and section header table overlap.");
            }
        }

        //
        // Parsing program header
        //
        {
            for (decltype(Elf64_Ehdr::e_phnum) i = 0; i < Interpreter.m_lpElfHdr->e_phnum; ++i) {
                const auto& proghdr = Interpreter.m_lpElfProgramHdr[i];

                if (ARL::AddressIsInRangeEx(ARL::AddressOffset(lpImage, proghdr.p_offset), proghdr.p_filesz, lpImage, cbImage) == false) {
                    throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: image is corrupted.");
                }

                if (auto p_align = proghdr.p_align; p_align) {
                    // align must be a power of 2
                    if ((p_align & (p_align - 1)) != 0) {
                        throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Phdr[%u]: p_align is not a power of 2.", i);
                    }

                    if (proghdr.p_offset % p_align != proghdr.p_vaddr % p_align) {
                        throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Phdr[%u]: p_offset !== p_vaddr (mod p_align).", i);
                    }
                }

                // todo
            }
        }

        // 
        // Parsing section header
        //
        {
            const Elf64_Shdr* sechdr_shstrtab;
            const char* secview_shstrtab;
            if (Interpreter.m_lpElfHdr->e_shstrndx != SHN_UNDEF) {
                sechdr_shstrtab = &Interpreter.m_lpElfSectionHdr[Interpreter.m_lpElfHdr->e_shstrndx];
                secview_shstrtab = ARL::AddressOffsetWithCast<const char*>(lpImage, sechdr_shstrtab->sh_offset);

                if (sechdr_shstrtab->sh_type != SHT_STRTAB) {
                    throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: sechdr_shstrtab->sh_type != SHT_STRTAB.");
                }

                if (ARL::AddressIsInRangeEx(secview_shstrtab, sechdr_shstrtab->sh_size, lpImage, cbImage) == false) {
                    throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: image is corrupted.");
                }
            } else {
                sechdr_shstrtab = nullptr;
                secview_shstrtab = nullptr;
            }

            for (decltype(Elf64_Ehdr::e_shnum) i = 0; i < Interpreter.m_lpElfHdr->e_shnum; ++i) {
                auto& sechdr = Interpreter.m_lpElfSectionHdr[i];

                //
                // checking sh_type
                //
                switch (sechdr.sh_type) {
                    case SHT_SYMTAB:
                        if (sechdr.sh_entsize != sizeof(Elf64_Sym)) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_entsize != sizeof(Elf64_Dyn).", i);
                        }
                        break;
                    case SHT_RELA:
                        if (sechdr.sh_entsize != sizeof(Elf64_Rela)) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_entsize != sizeof(Elf64_Rela).", i);
                        }
                        break;
                    case SHT_DYNAMIC:
                        if (sechdr.sh_entsize != sizeof(Elf64_Dyn)) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_entsize != sizeof(Elf64_Dyn).", i);
                        }
                        break;
                    case SHT_REL:
                        if (sechdr.sh_entsize != sizeof(Elf64_Rel)) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_entsize != sizeof(Elf64_Rel).", i);
                        }
                        break;
                    case SHT_DYNSYM:
                        if (sechdr.sh_entsize != sizeof(Elf64_Sym)) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_entsize != sizeof(Elf64_Dyn).", i);
                        }
                        break;
                    default:
                        break;
                }

                //
                // checking sh_link and sh_info
                //
                switch (sechdr.sh_type) {
                    case SHT_DYNAMIC:
                        if (sechdr.sh_link == SHN_UNDEF) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_link == SHN_UNDEF.", i);
                        }

                        if (sechdr.sh_link < Interpreter.m_lpElfHdr->e_shnum) {
                            if (Interpreter.m_lpElfSectionHdr[sechdr.sh_link].sh_type != SHT_STRTAB) {
                                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: incorrect value of sh_link.", i);
                            }
                        } else {
                            throw ARL::IndexError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_link is out of range.", i);
                        }

                        if (sechdr.sh_info != 0) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_info != 0.", i);
                        }
                        break;
                    case SHT_HASH:
                        if (sechdr.sh_link == SHN_UNDEF) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_link == SHN_UNDEF.", i);
                        }

                        if (sechdr.sh_link < Interpreter.m_lpElfHdr->e_shnum) {
                            if (Interpreter.m_lpElfSectionHdr[sechdr.sh_link].sh_type != SHT_SYMTAB && Interpreter.m_lpElfSectionHdr[sechdr.sh_link].sh_type != SHT_DYNSYM) {
                                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: incorrect value of sh_link.", i);
                            }
                        } else {
                            throw ARL::IndexError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_link is out of range.", i);
                        }

                        if (sechdr.sh_info != 0) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_info != 0.", i);
                        }
                        break;
                    case SHT_RELA:
                    case SHT_REL:
                        if (sechdr.sh_link == SHN_UNDEF) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_link == SHN_UNDEF.", i);
                        }

                        if (sechdr.sh_link < Interpreter.m_lpElfHdr->e_shnum) {
                            if (Interpreter.m_lpElfSectionHdr[sechdr.sh_link].sh_type != SHT_SYMTAB && Interpreter.m_lpElfSectionHdr[sechdr.sh_link].sh_type != SHT_DYNSYM) {
                                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: incorrect value of sh_link.", i);
                            }
                        } else {
                            throw ARL::IndexError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_link is out of range.", i);
                        }

                        if (sechdr.sh_flags & SHF_INFO_LINK) {
                            if (sechdr.sh_info == SHN_UNDEF) {
                                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_info == SHN_UNDEF.", i);
                            }

                            if (sechdr.sh_info >= Interpreter.m_lpElfHdr->e_shnum) {
                                throw ARL::IndexError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_info is out of range.", i);
                            }
                        } else {
                            if (sechdr.sh_info != 0) {
                                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_info != 0.", i);
                            }
                        }
                        break;
                    case SHT_SYMTAB:
                    case SHT_DYNSYM:
                        if (sechdr.sh_link == SHN_UNDEF) {
                            throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_link == SHN_UNDEF.", i);
                        }

                        if (sechdr.sh_link < Interpreter.m_lpElfHdr->e_shnum) {
                            if (Interpreter.m_lpElfSectionHdr[sechdr.sh_link].sh_type != SHT_STRTAB) {
                                throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: incorrect value of sh_link.", i);
                            }
                        } else {
                            throw ARL::IndexError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_link is out of range.", i);
                        }

                        // todo: check sh_info
                        break;
                    default:
                        break;
                }

                if (sechdr.sh_type != SHT_NOBITS) {
                    if (ARL::AddressIsInRangeEx(ARL::AddressOffset(lpImage, sechdr.sh_offset), sechdr.sh_size, lpImage, cbImage) == false) {
                        throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: image is corrupted.", i);
                    }
                }

                if (sechdr.sh_addr) {
                    if (sechdr.sh_addralign && sechdr.sh_addr % sechdr.sh_addralign != 0) {
                        throw ARL::AssertionError(__BASE_FILE__, __LINE__, "Bad ELF file: Elf64_Shdr[%u]: sh_addr is not aligned to sh_addralign.", i);
                    }

                    Interpreter.m_SectionRvaMap.emplace(
                        std::make_pair(
                            sechdr.sh_addr,
                            Interpreter.m_lpElfSectionHdr + i
                        )
                    );
                }

                if (sechdr.sh_type != SHT_NOBITS) {
                    Interpreter.m_SectionOffsetMap.emplace(
                        std::make_pair(
                            sechdr.sh_offset,
                            Interpreter.m_lpElfSectionHdr + i
                        )
                    );
                }

                if (secview_shstrtab) {
                    Interpreter.m_SectionNameMap.emplace(
                        std::make_pair(
                            std::string(ARL::AddressOffset(secview_shstrtab, sechdr.sh_name)),
                            Interpreter.m_lpElfSectionHdr + i
                        )
                    );
                }

                // todo
            }
        }

        return Interpreter;
    }

    size_t Elf64Interpreter::ElfSize() const noexcept {
        return m_ElfSize;
    }

    [[nodiscard]]
    const Elf64_Phdr* Elf64Interpreter::ElfProgramHeader(size_t Idx) const {
        if (Idx < m_lpElfHdr->e_phnum) {
            return m_lpElfProgramHdr + Idx;
        } else {
            throw ARL::IndexError(__BASE_FILE__, __LINE__, "Elf64Interpreter: Idx is out of range.");
        }
    }

    [[nodiscard]]
    const Elf64_Shdr* Elf64Interpreter::ElfSectionHeader(size_t Idx) const {
        if (Idx < m_lpElfHdr->e_shnum) {
            return m_lpElfSectionHdr + Idx;
        } else {
            throw ARL::IndexError(__BASE_FILE__, __LINE__, "Elf64Interpreter: Idx is out of range.");
        }
    }

    [[nodiscard]]
    const Elf64_Shdr* Elf64Interpreter::ElfSectionHeader(std::string_view SectionName) const {
        auto it = m_SectionNameMap.find(std::string(SectionName));
        if (it != m_SectionNameMap.end()) {
            return it->second;
        } else {
            throw ARL::KeyError(__BASE_FILE__, __LINE__, "Elf64Interpreter: section %s is not found.", SectionName.data());
        }
    }

    [[nodiscard]]
    Elf64_Off Elf64Interpreter::ConvertRvaToOffset(Elf64_Addr Rva) const {
        auto it = m_SectionRvaMap.upper_bound(Rva);
        if (it != m_SectionRvaMap.begin()) {
            --it;
            if (it->second->sh_addr <= Rva && Rva < it->second->sh_addr + it->second->sh_size) {
                return it->second->sh_offset + (Rva - it->second->sh_addr);
            }
        }
        throw ARL::KeyError(__BASE_FILE__, __LINE__, "Elf64Interpreter: Invalid RVA.");
    }

    [[nodiscard]]
    Elf64_Addr Elf64Interpreter::ConvertOffsetToRva(Elf64_Off Offset) const {
        auto it = m_SectionOffsetMap.upper_bound(Offset);
        if (it != m_SectionOffsetMap.begin()) {
            --it;
            if (it->second->sh_offset <= Offset && Offset < it->second->sh_offset + it->second->sh_size) {
                return it->second->sh_addr + (Offset - it->second->sh_offset);
            }
        }
        throw ARL::KeyError(__BASE_FILE__, __LINE__, "Elf64Interpreter: Invalid Offset.");
    }
}

