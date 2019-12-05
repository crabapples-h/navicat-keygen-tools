#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __APPLE__
    #include <libelf/libelf.h>
#else
    #include <elf.h>
#endif
#include <string>
#include <vector>
#include <map>
#include <type_traits>
#include <utility>
#include "MemoryAccess.hpp"

namespace nkg {

    class Elf64Interpreter {
    private:

        size_t              m_ElfSize;
        const Elf64_Ehdr*   m_lpElfHdr;
        const Elf64_Phdr*   m_lpElfProgramHdr;
        const Elf64_Shdr*   m_lpElfSectionHdr;
        std::map<Elf64_Addr, const Elf64_Shdr*>     m_SectionRvaMap;
        std::map<Elf64_Off, const Elf64_Shdr*>      m_SectionOffsetMap;
        std::map<std::string, const Elf64_Shdr*>    m_SectionNameMap;

    protected:

        Elf64Interpreter() :
            m_ElfSize(0),
            m_lpElfHdr(nullptr),
            m_lpElfProgramHdr(nullptr),
            m_lpElfSectionHdr(nullptr) {}

    public:

        [[nodiscard]]
        static Elf64Interpreter Parse(const void* lpImage, size_t cbImage);

        size_t ElfSize() const noexcept;

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ElfBase() const noexcept {
            static_assert(std::is_pointer_v<__ReturnType>);
            return reinterpret_cast<__ReturnType>(const_cast<Elf64_Ehdr*>(m_lpElfHdr));
        }

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ElfOffset(Elf64_Off Offset) const noexcept {
            static_assert(std::is_pointer_v<__ReturnType>);
            return ARL::AddressOffsetWithCast<__ReturnType>(m_lpElfHdr, Offset);
        }

        [[nodiscard]]
        const Elf64_Ehdr* ElfHeader() const noexcept {
            return m_lpElfHdr;
        }

        [[nodiscard]]
        size_t NumberOfElfProgramHeaders() const noexcept {
            return m_lpElfHdr->e_phnum;
        }

        [[nodiscard]]
        const Elf64_Phdr* ElfProgramHeader(size_t Idx) const;

        [[nodiscard]]
        size_t NumberOfElfSectionHeaders() const noexcept {
            return m_lpElfHdr->e_shnum;
        }

        [[nodiscard]]
        const Elf64_Shdr* ElfSectionHeader(size_t Idx) const;

        [[nodiscard]]
        const Elf64_Shdr* ElfSectionHeader(std::string_view SectionName) const;

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ElfSectionView(const Elf64_Shdr* SectionHeader, Elf64_Off Offset = 0) const noexcept {
            return ElfOffset<__ReturnType>(SectionHeader->sh_offset + Offset);
        }

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ElfSectionView(size_t Idx, Elf64_Off Offset = 0) const noexcept {
            return ElfOffset<__ReturnType>(ElfSectionHeader(Idx)->sh_offset + Offset);
        }

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ElfSectionView(std::string_view SectionName, Elf64_Off Offset = 0) const noexcept {
            return ElfOffset<__ReturnType>(ElfSectionHeader(SectionName)->sh_offset + Offset);
        }

        //
        // Other
        //

        template<typename __ReturnType = void*, typename __HintType>
        __ReturnType SearchElfSectionView(const Elf64_Shdr* SectionHeader, __HintType&& Hint) const noexcept {
            auto secview = ElfSectionView<const uint8_t*>(SectionHeader);
            for (decltype(Elf64_Shdr::sh_size) i = 0; i < SectionHeader->sh_size; ++i) {
                if (Hint(secview, i, SectionHeader->sh_size)) {
                    return reinterpret_cast<__ReturnType>(const_cast<uint8_t*>(secview + i));
                }
            }
            return nullptr;
        }

        template<typename __ReturnType = void*, typename __HintType>
        __ReturnType SearchElfSectionView(const Elf64_Shdr* SectionHeader, Elf64_Off Offset, __HintType&& Hint) const noexcept {
            auto secview = ElfSectionView<const uint8_t*>(SectionHeader);
            for (decltype(Elf64_Shdr::sh_size) i = Offset; i < SectionHeader->sh_size; ++i) {
                if (Hint(secview, i, SectionHeader->sh_size)) {
                    return reinterpret_cast<__ReturnType>(const_cast<uint8_t*>(secview + i));
                }
            }
            return nullptr;
        }

        template<typename __ReturnType = void*, typename __HintType>
        __ReturnType SearchElfSectionView(size_t Idx, __HintType&& Hint) const noexcept {
            return SearchElfSectionView<__ReturnType>(ElfSectionHeader(Idx), std::forward<__HintType>(Hint));
        }

        template<typename __ReturnType = void*, typename __HintType>
        __ReturnType SearchElfSectionView(size_t Idx, Elf64_Off Offset, __HintType&& Hint) const noexcept {
            return SearchElfSectionView<__ReturnType>(ElfSectionHeader(Idx), Offset, std::forward<__HintType>(Hint));
        }

        template<typename __ReturnType = void*, typename __HintType>
        __ReturnType SearchElfSectionView(std::string_view SectionName, __HintType&& Hint) const noexcept {
            return SearchElfSectionView<__ReturnType>(ElfSectionHeader(SectionName), std::forward<__HintType>(Hint));
        }

        template<typename __ReturnType = void*, typename __HintType>
        __ReturnType SearchElfSectionView(std::string_view SectionName, Elf64_Off Offset, __HintType&& Hint) const noexcept {
            return SearchElfSectionView<__ReturnType>(ElfSectionHeader(SectionName), Offset, std::forward<__HintType>(Hint));
        }

        [[nodiscard]]
        const auto& ElfSectionRvaMap() const noexcept {
            return m_SectionRvaMap;
        }

        [[nodiscard]]
        const auto& ElfSectionOffsetMap() const noexcept {
            return m_SectionOffsetMap;
        }

        [[nodiscard]]
        const auto& ElfSectionNameMap() const noexcept {
            return m_SectionNameMap;
        }

        [[nodiscard]]
        Elf64_Off ConvertRvaToOffset(Elf64_Addr Rva) const;

        template<typename __PtrType>
        [[nodiscard]]
        Elf64_Off ConvertPtrToOffset(__PtrType Ptr) const {
            return ARL::AddressDelta(Ptr, m_lpElfHdr);
        }

        [[nodiscard]]
        Elf64_Addr ConvertOffsetToRva(Elf64_Off Offset) const;

        template<typename __PtrType>
        [[nodiscard]]
        Elf64_Addr ConvertPtrToRva(__PtrType Ptr) const {
            return ConvertOffsetToRva(ConvertPtrToOffset(Ptr));
        }

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ConvertRvaToPtr(Elf64_Addr Rva) const {
            return ConvertOffsetToPtr<__ReturnType>(ConvertRvaToOffset(Rva));
        }

        template<typename __ReturnType = void*>
        [[nodiscard]]
        __ReturnType ConvertOffsetToPtr(Elf64_Off Offset) const {
            return ElfOffset<__ReturnType>(Offset);
        }
    };

}

