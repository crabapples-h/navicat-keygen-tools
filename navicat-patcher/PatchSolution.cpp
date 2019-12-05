#include "PatchSolutions.hpp"

namespace nkg {

    void PatchSolution::SearchFreeSpace(std::map<Elf64_Off, Elf64_Xword>& SpaceMap, const Elf64Interpreter& Image) {
        static auto lpfnUpdateMap = [](std::map<Elf64_Off, Elf64_Xword>& SpaceMap, Elf64_Off offset, Elf64_Xword size) {
            auto start = offset;
            auto end = start + size;
            while (size) {
                auto space = SpaceMap.upper_bound(offset);
                auto space_start = space->first;
                auto space_end = space_start + space->second;
                if (space != SpaceMap.end() && space_start < end) { // implicit condition: start < space_start
                    if (space_end <= end) {
                        SpaceMap.erase(space);
                    } else {
                        auto node = SpaceMap.extract(space);
                        node.key() = end;
                        SpaceMap.insert(std::move(node));
                    }
                } else if (space != SpaceMap.begin()) {
                    --space;
                    space_start = space->first;                 // space_start <= start
                    space_end = space_start + space->second;
                    if (start < space_end) {
                        space->second = start - space_start;
                        if (space->second == 0) {
                            SpaceMap.erase(space);
                        }
                        if (end < space_end) {
                            SpaceMap.emplace(end, space_end - end);
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        };

        lpfnUpdateMap(SpaceMap, 0, sizeof(Elf64_Ehdr));
        lpfnUpdateMap(SpaceMap, Image.ElfHeader()->e_phoff, Image.ElfHeader()->e_phentsize * Image.ElfHeader()->e_phnum);
        lpfnUpdateMap(SpaceMap, Image.ElfHeader()->e_shoff, Image.ElfHeader()->e_shentsize * Image.ElfHeader()->e_shnum);
        for (size_t i = 0; i < Image.NumberOfElfProgramHeaders(); ++i) {
            auto seg_hdr = Image.ElfProgramHeader(i);
            if (seg_hdr->p_type != PT_NULL) {
                lpfnUpdateMap(SpaceMap, seg_hdr->p_offset, seg_hdr->p_filesz);
            }
        }

        for (size_t i = 0; i < Image.NumberOfElfSectionHeaders(); ++i) {
            auto sec_hdr = Image.ElfSectionHeader(i);
            if (sec_hdr->sh_type != SHT_NULL && sec_hdr->sh_type != SHT_NOBITS) {
                lpfnUpdateMap(SpaceMap, sec_hdr->sh_offset, sec_hdr->sh_size);
            }
        }
    }

}

