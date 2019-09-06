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
        std::map<uintptr_t, size_t> _SectionAddressTable;
        std::map<uintptr_t, size_t> _SectionOffsetTable;
        std::map<uintptr_t, size_t> _RelocationAddressTable;
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
        PIMAGE_SECTION_HEADER   ImageSectionHeader(PCSTR lpszSectionName) const;

        [[nodiscard]]
        PIMAGE_SECTION_HEADER   ImageSectionHeader(uintptr_t Rva) const;

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType ImageSectionView(PCSTR lpszSectionName, size_t Offset = 0) const {
            return ImageOffset<__PtrType>(ImageSectionHeader(lpszSectionName)->PointerToRawData + Offset);
        }

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType ImageSectionView(PIMAGE_SECTION_HEADER SectionHeader, size_t Offset = 0) const {
            return ImageOffset<__PtrType>(SectionHeader->PointerToRawData + Offset);
        }

        template<typename __ReturnType, typename __Hint>
        [[nodiscard]]
        __ReturnType SearchSection(PCSTR lpszSectionName, __Hint&& Hint) const {
            return SearchSection<__ReturnType>(ImageSectionHeader(lpszSectionName), std::forward<__Hint>(Hint));
        }

        template<typename __ReturnType, typename __Hint>
        [[nodiscard]]
        __ReturnType SearchSection(PCSTR lpszSectionName, size_t Offset, __Hint&& Hint) const {
            return SearchSection<__ReturnType>(ImageSectionHeader(lpszSectionName), Offset, std::forward<__Hint>(Hint));
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

        [[nodiscard]]
        uintptr_t RvaToFileOffset(uintptr_t Rva) const;

        [[nodiscard]]
        uintptr_t FileOffsetToRva(uintptr_t FileOffset) const;

        template<typename __PtrType = PVOID>
        [[nodiscard]]
        __PtrType RvaToPointer(uintptr_t Rva) const {
            static_assert(std::is_pointer_v<__PtrType>);
            return ImageOffset<__PtrType>(RvaToFileOffset(Rva));
        }

        template<typename __PtrType>
        [[nodiscard]]
        uintptr_t PointerToRva(__PtrType Ptr) const {
            static_assert(std::is_pointer_v<__PtrType>);
            return FileOffsetToRva(reinterpret_cast<const volatile char*>(Ptr) - reinterpret_cast<const volatile char*>(_DosHeader));
        }

        template<typename __PtrType>
        [[nodiscard]]
        __PtrType FileOffsetToPointer(uintptr_t FileOffset) const noexcept {
            return ImageOffset<__PtrType>(FileOffset);
        }

        template<typename __PtrType>
        [[nodiscard]]
        uintptr_t PointerToFileOffset(__PtrType Ptr) const noexcept {
            static_assert(std::is_pointer_v<__PtrType>);
            return reinterpret_cast<const volatile char*>(Ptr) - reinterpret_cast<const volatile char*>(_DosHeader);
        }

        [[nodiscard]]
        bool IsRvaRangeInRelocTable(uintptr_t Rva, size_t Size) const;

        [[nodiscard]]
        DWORD ImageFileMajorVersion() const;

        [[nodiscard]]
        DWORD ImageFileMinorVersion() const;

        [[nodiscard]]
        DWORD ImageProductMajorVersion() const;

        [[nodiscard]]
        DWORD ImageProductMinorVersion() const;
    };

}

