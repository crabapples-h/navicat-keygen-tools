#pragma once
#include <stddef.h>
#include <stdint.h>
#include <Exception.hpp>
#include <windows.h>
#include <map>
#include <utility>
#include <type_traits>

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\ImageInterpreter.hpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    class ImageInterpreter {
    private:

        PIMAGE_DOS_HEADER _DosHeader;
        PIMAGE_NT_HEADERS _NtHeaders;
        PIMAGE_SECTION_HEADER _SectionHeaderTable;
        std::map<uint64_t, size_t> _SectionNameTable;
        std::map<uintptr_t, size_t> _SectionRvaTable;
        std::map<uintptr_t, size_t> _SectionFileOffsetTable;
        std::map<uintptr_t, size_t> _RelocationRvaTable;
        VS_FIXEDFILEINFO* _VsFixedFileInfo;

        ImageInterpreter();

    public:

        [[nodiscard]]
        static ImageInterpreter ParseImage(PVOID PtrToImageBase, bool DisableRelocationParsing = false);

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType ImageBase() const noexcept {
            static_assert(std::is_pointer_v<__PtrType>);
            return reinterpret_cast<__PtrType>(_DosHeader);
        }

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType ImageOffset(size_t Offset) const noexcept {
            static_assert(std::is_pointer_v<__PtrType>);
            return reinterpret_cast<__PtrType>(reinterpret_cast<char*>(_DosHeader) + Offset);
        }

        [[nodiscard]]
        PIMAGE_DOS_HEADER       ImageDosHeader()    const noexcept;

        [[nodiscard]]
        PIMAGE_NT_HEADERS       ImageNtHeaders()    const noexcept;

        [[nodiscard]]
        PIMAGE_SECTION_HEADER   ImageSectionTable() const noexcept;

        [[nodiscard]]
        PIMAGE_SECTION_HEADER   ImageSectionHeader(size_t Idx) const;

        [[nodiscard]]
        PIMAGE_SECTION_HEADER   ImageSectionHeaderByName(PCSTR lpszSectionName) const;

        [[nodiscard]]
        PIMAGE_SECTION_HEADER   ImageSectionHeaderByRva(uintptr_t Rva) const;

        [[nodiscard]]
        PIMAGE_SECTION_HEADER   ImageSectionHeaderByVa(uintptr_t Va) const;

        [[nodiscard]]
        PIMAGE_SECTION_HEADER   ImageSectionHeaderByFileOffset(uintptr_t FileOffset) const;

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType ImageSectionView(PIMAGE_SECTION_HEADER SectionHeader, size_t Offset = 0) const noexcept {
            return ImageOffset<__PtrType>(SectionHeader->PointerToRawData + Offset);
        }

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType ImageSectionViewByName(PCSTR lpszSectionName, size_t Offset = 0) const {
            return ImageOffset<__PtrType>(ImageSectionHeaderByName(lpszSectionName)->PointerToRawData + Offset);
        }

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType ImageSectionViewByRva(uintptr_t Rva, size_t Offset = 0) const {
            return ImageOffset<__PtrType>(ImageSectionHeaderByRva(Rva)->PointerToRawData + Offset);
        }

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType ImageSectionViewByVa(uintptr_t Va, size_t Offset = 0) const {
            return ImageOffset<__PtrType>(ImageSectionHeaderByVa(Va)->PointerToRawData + Offset);
        }

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType ImageSectionViewByFileOffset(uintptr_t FileOffset, size_t Offset = 0) const {
            return ImageOffset<__PtrType>(ImageSectionHeaderByFileOffset(FileOffset)->PointerToRawData + Offset);
        }

        template<typename __ReturnType, typename __Hint>
        [[nodiscard]]
        __ReturnType SearchSection(PIMAGE_SECTION_HEADER SectionHeader, __Hint&& Hint) const {
            static_assert(std::is_pointer_v<__ReturnType>);

            auto begin = ImageSectionView<const uint8_t*>(SectionHeader);
            auto end = begin + SectionHeader->Misc.VirtualSize;

            for (; begin < end; ++begin) {
                if (Hint(begin) == true) {
                    return reinterpret_cast<__ReturnType>(const_cast<uint8_t*>(begin));
                }
            }

            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Data is not found."));
        }

        template<typename __ReturnType, typename __Hint>
        [[nodiscard]]
        __ReturnType SearchSection(PIMAGE_SECTION_HEADER SectionHeader, size_t Offset, __Hint&& Hint) const {
            static_assert(std::is_pointer_v<__ReturnType>);

            auto begin = ImageSectionView<const uint8_t*>(SectionHeader) + Offset;
            auto end = begin + SectionHeader->Misc.VirtualSize;

            for (; begin < end; ++begin) {
                if (Hint(begin) == true) {
                    return reinterpret_cast<__ReturnType>(const_cast<uint8_t*>(begin));
                }
            }

            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Data is not found."));
        }

        template<typename __ReturnType, typename __Hint>
        [[nodiscard]]
        __ReturnType SearchSection(PCSTR lpszSectionName, __Hint&& Hint) const {
            return SearchSection<__ReturnType>(ImageSectionHeaderByName(lpszSectionName), std::forward<__Hint>(Hint));
        }

        template<typename __ReturnType, typename __Hint>
        [[nodiscard]]
        __ReturnType SearchSection(PCSTR lpszSectionName, size_t Offset, __Hint&& Hint) const {
            return SearchSection<__ReturnType>(ImageSectionHeaderByName(lpszSectionName), Offset, std::forward<__Hint>(Hint));
        }

        [[nodiscard]]
        uintptr_t RvaToVa(uintptr_t Rva) const noexcept;

        [[nodiscard]]
        uintptr_t RvaToFileOffset(uintptr_t Rva) const;

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType RvaToPointer(uintptr_t Rva) const {
            static_assert(std::is_pointer_v<__PtrType>);
            return ImageOffset<__PtrType>(RvaToFileOffset(Rva));
        }

        [[nodiscard]]
        uintptr_t FileOffsetToRva(uintptr_t FileOffset) const;

        [[nodiscard]]
        uintptr_t FileOffsetToVa(uintptr_t FileOffset) const;

        template<typename __PtrType>
        [[nodiscard]]
        __PtrType FileOffsetToPointer(uintptr_t FileOffset) const noexcept {
            return ImageOffset<__PtrType>(FileOffset);
        }

        [[nodiscard]]
        uintptr_t VaToRva(uintptr_t Va) const noexcept;

        [[nodiscard]]
        uintptr_t VaToFileOffset(uintptr_t Va) const;

        template<typename __PtrType>
        [[nodiscard]]
        __PtrType VaToPointer(uintptr_t Va) const noexcept {
            return RvaToPointer<__PtrType>(VaToRva(Va));
        }

        template<typename __PtrType>
        [[nodiscard]]
        uintptr_t PointerToFileOffset(__PtrType Ptr) const noexcept {
            static_assert(std::is_pointer_v<__PtrType>);
            return reinterpret_cast<const volatile char*>(Ptr) - reinterpret_cast<const volatile char*>(_DosHeader);
        }

        template<typename __PtrType>
        [[nodiscard]]
        uintptr_t PointerToRva(__PtrType Ptr) const {
            return FileOffsetToRva(PointerToFileOffset(Ptr));
        }

        template<typename __PtrType>
        [[nodiscard]]
        uintptr_t PointerToVa(__PtrType Ptr) const {
            return FileOffsetToVa(PointerToFileOffset(Ptr));
        }

        [[nodiscard]]
        bool IsRvaRangeInRelocTable(uintptr_t Rva, size_t Size) const;

        [[nodiscard]]
        bool IsVaRangeInRelocTable(uintptr_t Va, size_t Size) const;

        [[nodiscard]]
        bool IsFileOffsetRangeInRelocTable(uintptr_t FileOffset, size_t Size) const;

        template<typename __PtrType>
        [[nodiscard]]
        bool IsFileOffsetRangeInRelocTable(__PtrType Ptr, size_t Size) const {
            return IsRvaRangeInRelocTable(PointerToRva(Ptr), Size);
        }

        [[nodiscard]]
        DWORD ImageFileMajorVersion() const;

        [[nodiscard]]
        DWORD ImageFileMinorVersion() const;

        [[nodiscard]]
        DWORD ImageProductMajorVersion() const;

        [[nodiscard]]
        DWORD ImageProductMinorVersion() const;

        [[nodiscard]]
        size_t NumberOfSections() const noexcept;
    };

}

