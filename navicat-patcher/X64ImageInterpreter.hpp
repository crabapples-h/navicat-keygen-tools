#pragma once
#include <string.h> // NOLINT
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <vector>
#include <map>
#include "../common/Exception.hpp"

class X64ImageInterpreter {
public:
    static constexpr uint64_t InvalidAddress = static_cast<uint64_t>(-1);
    static constexpr uint32_t InvalidOffset = static_cast<uint32_t>(-1);
private:

    mach_header_64*                     pvt_MachHeader;
    std::vector<segment_command_64*>    pvt_SegmentCommands;

    struct {
        std::map<size_t, section_64*>   ByIndex;
        std::map<uint64_t, section_64*> ByMapAddress;
        std::map<uint32_t, section_64*> ByFileOffset;
    } pvt_Sections;

    struct {
        dysymtab_command* SegmentCommand;
    } pvt_DynamicSymbol;

    struct {
        symtab_command* SegmentCommand;
        char*           StringTable;
        nlist_64*       SymbolTable;
    } pvt_Symbol;

    struct {
        dyld_info_command* SegmentCommand;
    } pvt_DynamicLoaderInfoOnly;

    X64ImageInterpreter() :
        pvt_MachHeader(nullptr),
        pvt_DynamicSymbol{},
        pvt_Symbol{},
        pvt_DynamicLoaderInfoOnly{} {}

public:

    [[nodiscard]]
    static X64ImageInterpreter Parse(void* ImageBase);

    template<typename __ReturnType = void*>
    [[nodiscard]]
    __ReturnType ImageBase() const noexcept {
        static_assert(std::is_pointer_v<__ReturnType>);
        return reinterpret_cast<__ReturnType>(pvt_MachHeader);
    }

    template<typename __ReturnType = void*>
    [[nodiscard]]
    __ReturnType ImageOffset(size_t Offset) const noexcept {
        static_assert(std::is_pointer_v<__ReturnType>);
        return reinterpret_cast<__ReturnType>(
            reinterpret_cast<uint8_t*>(pvt_MachHeader) + Offset
        );
    }

    template<unsigned __CommandMacro>
    [[nodiscard]]
    auto CommandOf() const noexcept {
        if constexpr (__CommandMacro == LC_DYSYMTAB) {
            return pvt_DynamicSymbol.SegmentCommand;
        } else if constexpr (__CommandMacro == LC_SYMTAB) {
            return pvt_Symbol.SegmentCommand;
        } else if constexpr (__CommandMacro == LC_DYLD_INFO_ONLY) { // NOLINT
            return pvt_DynamicLoaderInfoOnly.SegmentCommand;
        } else {
            return nullptr;
        }
    }

    [[nodiscard]]
    size_t NumberOfSections() const noexcept;

    [[nodiscard]]
    section_64* ImageSection(size_t Index) const;

    [[nodiscard]]
    section_64* ImageSection(const char* SegmentName, const char* SectionName) const;

    [[nodiscard]]
    section_64* ImageSectionByOffset(uint32_t Offset) const;

    [[nodiscard]]
    section_64* ImageSectionByRva(uint64_t Rva) const;

    template<typename __ReturnType>
    [[nodiscard]]
    __ReturnType SectionView(size_t Index) const {
        auto Section = ImageSection(Index);
        return ImageOffset<__ReturnType>(Section->offset);
    }

    template<typename __ReturnType>
    [[nodiscard]]
    __ReturnType SectionView(const char* SegmentName, const char* SectionName) const {
        auto Section = ImageSection(SegmentName, SectionName);
        return ImageOffset<__ReturnType>(Section->offset);
    }

    template<typename __ReturnType>
    [[nodiscard]]
    __ReturnType SectionView(section_64* Section) const {
        return ImageOffset<__ReturnType>(Section->offset);
    }

    template<typename __ReturnType, typename __Hint>
    [[nodiscard]]
    __ReturnType SearchSection(size_t Index, __Hint&& Hint) const {
        return SearchSection<__ReturnType>(ImageSection(Index), std::forward<__Hint>(Hint));
    }

    template<typename __ReturnType, typename __Hint>
    [[nodiscard]]
    __ReturnType SearchSection(const char* SegmentName, const char* SectionName, __Hint&& Hint) const {
        return SearchSection<__ReturnType>(ImageSection(SegmentName, SectionName), std::forward<__Hint>(Hint));
    }

    template<typename __ReturnType, typename __Hint>
    [[nodiscard]]
    __ReturnType SearchSection(section_64* Section, __Hint&& Hint) const {
        static_assert(std::is_pointer_v<__ReturnType>);

        auto begin = SectionView<const uint8_t*>(Section);
        auto end = begin + Section->size;

        for (; begin < end; ++begin) {
            if (Hint(begin) == true) {
                return reinterpret_cast<__ReturnType>(const_cast<uint8_t*>(begin));
            }
        }

        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "Data is not found.");
    }

    template<typename __Hint>
    [[nodiscard]]
    uint32_t SearchSectionOffset(size_t Index, __Hint&& Hint) const {
        return SearchSection<uint8_t*>(Index, std::forward<__Hint>(Hint)) - ImageBase<uint8_t*>();
    }

    template<typename __Hint>
    [[nodiscard]]
    uint32_t SearchSectionOffset(const char* SegmentName, const char* SectionName, __Hint&& Hint) const {
        return SearchSection<uint8_t*>(SegmentName, SectionName, std::forward<__Hint>(Hint)) - ImageBase<uint8_t*>();
    }

    template<typename __Hint>
    [[nodiscard]]
    uint32_t SearchSectionOffset(section_64* Section, __Hint&& Hint) const {
        return SearchSection<uint8_t*>(Section, std::forward<__Hint>(Hint)) - ImageBase<uint8_t*>();
    }

    template<typename __Hint>
    [[nodiscard]]
    uint64_t SearchSectionRva(size_t Index, __Hint&& Hint) const {
        auto Section = ImageSection(Index);
        auto Offset = SearchSection<uint8_t*>(Section, std::forward<__Hint>(Hint)) - SectionView<uint8_t*>(Section);
        return Section->addr + Offset;
    }

    template<typename __Hint>
    [[nodiscard]]
    uint64_t SearchSectionRva(const char* SegmentName, const char* SectionName, __Hint&& Hint) const {
        auto Section = ImageSection(SegmentName, SectionName);
        auto Offset = SearchSection<uint8_t*>(Section, std::forward<__Hint>(Hint)) - SectionView<uint8_t*>(Section);
        return Section->addr + Offset;
    }

    template<typename __Hint>
    [[nodiscard]]
    uint64_t SearchSectionRva(section_64* Section, __Hint&& Hint) const {
        auto Offset = SearchSection<uint8_t*>(Section, std::forward<__Hint>(Hint)) - SectionView<uint8_t*>(Section);
        return Section->addr + Offset;
    }

    [[nodiscard]]
    uint64_t OffsetToRva(uint32_t Offset) const;

    [[nodiscard]]
    uint32_t RvaToOffset(uint64_t Address) const;

    [[nodiscard]]
    nlist_64* ImageSymbolTable() const noexcept;

    [[nodiscard]]
    char* LookupStringTable(size_t Offset) const noexcept {
        return pvt_Symbol.StringTable + Offset;
    }
};

