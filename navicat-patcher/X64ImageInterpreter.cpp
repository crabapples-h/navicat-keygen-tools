#include "X64ImageInterpreter.hpp"

[[nodiscard]]
X64ImageInterpreter X64ImageInterpreter::Parse(void* ImageBase) {
    X64ImageInterpreter NewImage;

    NewImage.pvt_MachHeader = reinterpret_cast<mach_header_64*>(ImageBase);
    if (NewImage.pvt_MachHeader->magic != MH_MAGIC_64) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "Bad Image");
    }

    auto cmd_p = reinterpret_cast<load_command*>(NewImage.pvt_MachHeader + 1);
    for (uint32_t i = 0; i < NewImage.pvt_MachHeader->ncmds; ++i) {
        switch (cmd_p->cmd) {
            case LC_SEGMENT_64: {
                auto segcmd_p = reinterpret_cast<segment_command_64*>(cmd_p);
                auto section_p = reinterpret_cast<section_64*>(segcmd_p + 1);

                NewImage.pvt_SegmentCommands.emplace_back(segcmd_p);

                for (uint32_t j = 0; j < segcmd_p->nsects; ++j) {
                    NewImage.pvt_Sections.ByIndex[NewImage.pvt_Sections.ByIndex.size()] = &section_p[j];
                    NewImage.pvt_Sections.ByMapAddress[section_p[j].addr] = &section_p[j];
                    NewImage.pvt_Sections.ByFileOffset[section_p[j].offset] = &section_p[j];
                }

                break;
            }
            case LC_DYSYMTAB: {
                NewImage.pvt_DynamicSymbol.SegmentCommand = reinterpret_cast<dysymtab_command*>(cmd_p);
                break;
            }
            case LC_SYMTAB: {
                NewImage.pvt_Symbol.SegmentCommand = reinterpret_cast<symtab_command*>(cmd_p);
                NewImage.pvt_Symbol.StringTable = NewImage.ImageOffset<char*>(NewImage.pvt_Symbol.SegmentCommand->stroff);
                NewImage.pvt_Symbol.SymbolTable = NewImage.ImageOffset<nlist_64*>(NewImage.pvt_Symbol.SegmentCommand->symoff);
                break;
            }
            case LC_DYLD_INFO_ONLY: {   // NOLINT
                NewImage.pvt_DynamicLoaderInfoOnly.SegmentCommand = reinterpret_cast<dyld_info_command*>(cmd_p);
            }
            default:
                break;
        }

        cmd_p = reinterpret_cast<load_command*>(
            reinterpret_cast<uint8_t*>(cmd_p) + cmd_p->cmdsize
        );
    }

    return NewImage;
}

[[nodiscard]]
size_t X64ImageInterpreter::NumberOfSections() const noexcept {
    return pvt_Sections.ByIndex.size();
}

[[nodiscard]]
section_64* X64ImageInterpreter::ImageSection(size_t Index) const {
    auto it = pvt_Sections.ByIndex.find(Index);
    if (it != pvt_Sections.ByIndex.cend()) {
        return it->second;
    } else {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "Section is not found.");
    }
}

[[nodiscard]]
section_64* X64ImageInterpreter::ImageSection(const char* SegmentName, const char* SectionName) const {
    for (auto segcmd_p : pvt_SegmentCommands) {
        if (strncmp(SegmentName, segcmd_p->segname, sizeof(segcmd_p->segname)) == 0) {
            auto sec_p = reinterpret_cast<section_64*>(segcmd_p + 1);

            for (uint32_t i = 0; i < segcmd_p->nsects; ++i) {
                if (strncmp(SectionName, sec_p[i].sectname, sizeof(sec_p[i].sectname)) == 0)
                    return &sec_p[i];
            }

            break;
        }
    }

    // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
    throw nkg::Exception(__FILE__, __LINE__, "Section is not found.");
}

[[nodiscard]]
section_64* X64ImageInterpreter::ImageSectionByOffset(uint32_t Offset) const {
    for (const auto& it : pvt_Sections.ByFileOffset) {
        if (it.first <= Offset && Offset < it.first + it.second->size) {
            return it.second;
        }
    }

    // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
    throw nkg::Exception(__FILE__, __LINE__, "Section is not found.");
}

[[nodiscard]]
section_64* X64ImageInterpreter::ImageSectionByRva(uint64_t Rva) const {
    for (const auto& it : pvt_Sections.ByMapAddress) {
        if (it.first <= Rva && Rva < it.first + it.second->size) {
            return it.second;
        }
    }

    // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
    throw nkg::Exception(__FILE__, __LINE__, "Section is not found.");
}

[[nodiscard]]
uint64_t X64ImageInterpreter::OffsetToRva(uint32_t Offset) const {
    auto section = ImageSectionByOffset(Offset);
    return section->addr + (Offset - section->offset);
}

[[nodiscard]]
uint32_t X64ImageInterpreter::RvaToOffset(uint64_t Rva) const {
    auto section = ImageSectionByRva(Rva);
    return section->offset + (Rva - section->addr);
}

[[nodiscard]]
nlist_64* X64ImageInterpreter::ImageSymbolTable() const noexcept {
    return pvt_Symbol.SymbolTable;
}


