#pragma once
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <vector>
#include <map>

#include "Exception.hpp"

class X64ImageInterpreter {
public:
    static constexpr uint64_t InvalidAddress = static_cast<uint64_t>(-1);
    static constexpr uint32_t InvalidOffset = static_cast<uint32_t>(-1);
private:
    mach_header_64*                     _$$_MachHeader;
    std::vector<segment_command_64*>    _$$_SegmentCommands;
    std::map<size_t, section_64*>       _$$_SectionIndexTable;
    std::map<uint64_t, section_64*>     _$$_SectionMapTable;
    std::map<uint32_t, section_64*>     _$$_SectionOffsetTable;
    dysymtab_command*                   _$$_DySymTabCommand;
    symtab_command*                     _$$_SymTabCommand;
    char*                               _$$_StringTable;
    nlist_64*                           _$$_SymbolTable;
    dyld_info_command*                  _$$_DyldInfoCommand;
public:

    X64ImageInterpreter() :
        _$$_MachHeader(nullptr),
        _$$_DySymTabCommand(nullptr),
        _$$_SymTabCommand(nullptr),
        _$$_StringTable(nullptr),
        _$$_SymbolTable(nullptr),
        _$$_DyldInfoCommand(nullptr) {}

    void LoadImage(void* ImageBase) {
        mach_header_64*                     MachHeader = nullptr;
        std::vector<segment_command_64*>    SegmentComamnds;
        std::map<size_t, section_64*>       SectionIndexTable;
        std::map<uint64_t, section_64*>     SectionMapTable;
        std::map<uint32_t, section_64*>     SectionOffsetTable;
        dysymtab_command*                   DySymTabCommand = nullptr;
        symtab_command*                     SymTabCommand = nullptr;
        char*                               StringTable = nullptr;
        nlist_64*                           SymbolTable = nullptr;
        dyld_info_command*                  DyldInfoCommand = nullptr;

        MachHeader = reinterpret_cast<mach_header_64*>(ImageBase);
        if (MachHeader->magic != MH_MAGIC_64) {
            throw Exception(__FILE__, __LINE__,
                            "Bad Image");
        }

        auto cmd_p = reinterpret_cast<load_command*>(MachHeader + 1);
        for (uint32_t i = 0; i < MachHeader->ncmds; ++i) {
            if (cmd_p->cmd == LC_SEGMENT_64) {
                auto segcmd_p = reinterpret_cast<segment_command_64*>(cmd_p);
                auto sec_p = reinterpret_cast<section_64*>(segcmd_p + 1);

                SegmentComamnds.emplace_back(segcmd_p);

                for (uint32_t j = 0; j < segcmd_p->nsects; ++j) {
                    SectionIndexTable[SectionIndexTable.size()] = &sec_p[j];
                    SectionMapTable[sec_p[j].addr] = &sec_p[j];
                    SectionOffsetTable[sec_p[j].offset] = &sec_p[j];
                }
            } else if (cmd_p->cmd == LC_DYSYMTAB) {
                DySymTabCommand = reinterpret_cast<dysymtab_command*>(cmd_p);
            } else if (cmd_p->cmd == LC_SYMTAB) {
                SymTabCommand = reinterpret_cast<symtab_command*>(cmd_p);
                StringTable = reinterpret_cast<char*>(ImageBase) + SymTabCommand->stroff;
                SymbolTable = reinterpret_cast<nlist_64*>(reinterpret_cast<uint8_t*>(ImageBase) + SymTabCommand->symoff);
            } else if (cmd_p->cmd == LC_DYLD_INFO_ONLY) {
                DyldInfoCommand = reinterpret_cast<dyld_info_command*>(cmd_p);
            }

            cmd_p = reinterpret_cast<load_command*>(
                reinterpret_cast<uint8_t*>(cmd_p) + cmd_p->cmdsize
            );
        }

        std::swap(_$$_MachHeader, MachHeader);
        std::swap(_$$_SegmentCommands, SegmentComamnds);
        std::swap(_$$_SectionIndexTable, SectionIndexTable);
        std::swap(_$$_SectionMapTable, SectionMapTable);
        std::swap(_$$_SectionOffsetTable, SectionOffsetTable);
        std::swap(_$$_DySymTabCommand, DySymTabCommand);
        std::swap(_$$_SymTabCommand, SymTabCommand);
        std::swap(_$$_StringTable, StringTable);
        std::swap(_$$_SymbolTable, SymbolTable);
        std::swap(_$$_DyldInfoCommand, DyldInfoCommand);
    }

    dysymtab_command* DySymTabCommand() const noexcept {
        return _$$_DySymTabCommand;
    }

    symtab_command* SymTabCommand() const noexcept {
        return _$$_SymTabCommand;
    }

    dyld_info_command* DyldInfoCommand() const noexcept {
        return _$$_DyldInfoCommand;
    }

    uint64_t OffsetToAddress(uint32_t Offset) const {
        auto sec_p = SectionByOffset(Offset);
        if (sec_p) {
            return sec_p->addr + (Offset - sec_p->offset);
        } else {
            return InvalidAddress;
        }
    }

    uint32_t AddressToOffset(uint64_t Address) const {
        auto sec_p = SectionByAddress(Address);
        if (sec_p) {
            return sec_p->offset + static_cast<uint32_t>(Address - sec_p->addr);
        } else {
            return InvalidOffset;
        }
    }

    section_64* SectionByIndex(size_t Index) const {
        auto it = _$$_SectionIndexTable.find(Index);
        return it != _$$_SectionIndexTable.cend() ? it->second : nullptr;
    }

    section_64* SectionByName(const char* SegmentName, const char* SectionName) const {
        if (_$$_MachHeader == nullptr)
            return nullptr;

        for (auto segcmd_p : _$$_SegmentCommands) {
            if (strncmp(SegmentName, segcmd_p->segname, 16) == 0) {
                auto sec_p = reinterpret_cast<section_64*>(segcmd_p + 1);
                for (uint32_t j = 0; j < segcmd_p->nsects; ++j) {
                    if (strncmp(SectionName, sec_p[j].sectname, 16) == 0)
                        return &sec_p[j];
                }
                return nullptr;
            }
        }

        return nullptr;
    }

    section_64* SectionByOffset(uint32_t Offset) const {
        if (!_$$_SectionOffsetTable.empty()) {
            auto upper = _$$_SectionOffsetTable.upper_bound(Offset);
            if (upper == _$$_SectionOffsetTable.cbegin())
                return nullptr;
            auto lower = std::prev(upper);

            if (lower->second->offset <= Offset && Offset < lower->second->offset + lower->second->size) {
                return lower->second;
            } else {
                return nullptr;
            }
        } else {
            return nullptr;
        }
    }

    section_64* SectionByAddress(uint64_t Address) const {
        if (!_$$_SectionMapTable.empty()) {
            auto upper = _$$_SectionMapTable.upper_bound(Address);
            if (upper == _$$_SectionMapTable.cbegin())
                return nullptr;
            auto lower = std::prev(upper);

            if (lower->second->addr <= Address && Address < lower->second->addr + lower->second->size) {
                return lower->second;
            } else {
                return nullptr;
            }
        } else {
            return nullptr;
        }
    }

    nlist_64* SymbolTable() const noexcept {
        return _$$_SymbolTable;
    }

    char* LookupStringTable(size_t Offset) const noexcept {
        return _$$_StringTable + Offset;
    }

    ~X64ImageInterpreter() {
        _$$_MachHeader = nullptr;
    }
};