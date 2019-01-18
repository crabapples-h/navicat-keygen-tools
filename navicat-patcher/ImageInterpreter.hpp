#pragma once
#include <windows.h>
#include <map>

#undef __BASE_FILE__
#define __BASE_FILE__ "ImageInterpreter.hpp"

class ImageInterpreter {
private:
    PVOID _PtrToImageBase;
    PIMAGE_NT_HEADERS _PtrToNTHeaders;
    PIMAGE_SECTION_HEADER _PtrToSectionHeaderTable;
    std::map<uint64_t, size_t> _SectionNameTable;
    std::map<uintptr_t, size_t> _SectionMapAddressTable;
    std::map<uintptr_t, size_t> _RelocationAddressTable;
public:

    bool ParseImage(const PVOID PtrToImageBase) {
        if (PtrToImageBase == nullptr)
            return false;

        PIMAGE_DOS_HEADER PtrToDosHeader = 
            reinterpret_cast<PIMAGE_DOS_HEADER>(PtrToImageBase);
        if (PtrToDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS PtrToNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<uint8_t*>(PtrToImageBase) +
            PtrToDosHeader->e_lfanew
        );
        if (PtrToNtHeaders->Signature != IMAGE_NT_SIGNATURE)
            return false;
        if (PtrToNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
            return false;
#if defined(_M_AMD64)
        if (PtrToNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
            return false;
#elif defined(_M_IX86)
        if (PtrToNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
            return false;
#else
#error "Unsupported architecture."
#endif

        PIMAGE_SECTION_HEADER PtrToSectionHeaderTable =
            reinterpret_cast<PIMAGE_SECTION_HEADER>(
                reinterpret_cast<char*>(&PtrToNtHeaders->OptionalHeader) +
                PtrToNtHeaders->FileHeader.SizeOfOptionalHeader
            );

        std::map<uint64_t, size_t> SectionNameTable;
        std::map<uintptr_t, size_t> SectioMapAddressTable;
        std::map<uintptr_t, size_t> RelocationAddressTable;

        for (WORD i = 0; i < PtrToNtHeaders->FileHeader.NumberOfSections; ++i) {
            uint64_t SectionName =
                *reinterpret_cast<uint64_t*>(PtrToSectionHeaderTable[i].Name);
            if (SectionNameTable.find(SectionName) != SectionNameTable.end())
                continue;
            SectionNameTable[SectionName] = i;


            uintptr_t SectionMapAddress =
                PtrToSectionHeaderTable[i].VirtualAddress;
            SectioMapAddressTable[SectionMapAddress] = i;
        }

        if (PtrToNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
            DWORD RelocTableRva = 
                PtrToNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            PIMAGE_BASE_RELOCATION PtrToRelocTable = nullptr;

            {
                auto v = SectioMapAddressTable.lower_bound(RelocTableRva);
                
                if (v != SectioMapAddressTable.end()) {
                    if (v->first != RelocTableRva) {
                        if (v != SectioMapAddressTable.begin()) {
                            --v;
                            PtrToRelocTable = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                                reinterpret_cast<uint8_t*>(PtrToImageBase) +
                                PtrToSectionHeaderTable[v->second].PointerToRawData
                            );
                        }
                    } else {
                        PtrToRelocTable = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                            reinterpret_cast<uint8_t*>(PtrToImageBase) +
                            PtrToSectionHeaderTable[v->second].PointerToRawData
                        );
                    }
                }
            }

            while (PtrToRelocTable != nullptr && PtrToRelocTable->VirtualAddress != 0) {
                DWORD Rva = PtrToRelocTable->VirtualAddress;
                PWORD RelocItems = reinterpret_cast<PWORD>(PtrToRelocTable + 1);
                DWORD RelocItemsCount = (PtrToRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (DWORD i = 0; i < RelocItemsCount; ++i) {
                    int RelocType = RelocItems[i] >> 12;
                    switch (RelocType) {
                        case IMAGE_REL_BASED_ABSOLUTE:
                            break;
                        case IMAGE_REL_BASED_HIGH:
                        case IMAGE_REL_BASED_LOW:
                        case IMAGE_REL_BASED_HIGHADJ:
                            RelocationAddressTable[Rva + (RelocItems[i] & 0x0fff)] = 2;
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            RelocationAddressTable[Rva + (RelocItems[i] & 0x0fff)] = 4;
                            break;
#if defined(IMAGE_REL_BASED_DIR64)
                        case IMAGE_REL_BASED_DIR64:
                            RelocationAddressTable[Rva + (RelocItems[i] & 0x0fff)] = 8;
                            break;
#endif
                        default:
                            break;
                    }
                }
                PtrToRelocTable = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                    &RelocItems[RelocItemsCount]
                );
            }
        }

        _PtrToImageBase = PtrToImageBase;
        _PtrToNTHeaders = PtrToNtHeaders;
        _PtrToSectionHeaderTable = PtrToSectionHeaderTable;
        _SectionNameTable = std::move(SectionNameTable);
        _SectionMapAddressTable = std::move(SectioMapAddressTable);
        _RelocationAddressTable = std::move(RelocationAddressTable);
        return true;
    }

    ImageInterpreter() :
        _PtrToImageBase(nullptr),
        _PtrToNTHeaders(nullptr),
        _PtrToSectionHeaderTable(nullptr) {}

    template<typename __Type>
    __Type* GetImageBaseView() const {
        return reinterpret_cast<__Type*>(_PtrToImageBase);
    }

    PIMAGE_NT_HEADERS GetImageNTHeaders() const {
        return _PtrToNTHeaders;
    }

    PIMAGE_SECTION_HEADER GetSectionHeaderTable() const {
        return _PtrToSectionHeaderTable;
    }

    PIMAGE_SECTION_HEADER GetSectionHeader(const char* SectionName) const {
        uint64_t NameValue = 0;
        
        for (int i = 0; i < sizeof(NameValue) && SectionName[i]; ++i)
            reinterpret_cast<char*>(&NameValue)[i] = SectionName[i];
        
        auto v = _SectionNameTable.find(NameValue);

        if (v == _SectionNameTable.end())
            return nullptr;
        else
            return &_PtrToSectionHeaderTable[v->second];
    }

    PIMAGE_SECTION_HEADER GetSectionHeader(uintptr_t Rva) const {
        auto v = _SectionMapAddressTable.lower_bound(Rva);
        
        if (v == _SectionMapAddressTable.end())
            return nullptr;

        if (v->first != Rva) {
            if (v == _SectionMapAddressTable.begin())
                return nullptr;
            --v;
            return &_PtrToSectionHeaderTable[v->second];
        } else {
            return &_PtrToSectionHeaderTable[v->second];
        }
    }

    template<typename __Type>
    __Type* GetSectionView(const char* SectionName) const {
        auto PtrToSectionHeader = GetSectionHeader(SectionName);

        if (PtrToSectionHeader == nullptr)
            return nullptr;

        return reinterpret_cast<__Type*>(
            reinterpret_cast<uint8_t*>(_PtrToImageBase) +
            PtrToSectionHeader->PointerToRawData
        );
    }

    template<typename __Type>
    __Type* GetSectionView(uintptr_t Rva) const {
        auto PtrToSectionHeader = GetSectionHeader(Rva);

        if (PtrToSectionHeader == nullptr)
            return nullptr;

        return reinterpret_cast<__Type*>(
            reinterpret_cast<uint8_t*>(_PtrToImageBase) +
            PtrToSectionHeader->PointerToRawData
        );
    }

    template<typename __Type>
    __Type* RvaToPointer(uintptr_t Rva) const {
        auto PtrToSectionHeader = GetSectionHeader(Rva);

        if (PtrToSectionHeader == nullptr)
            return nullptr;

        uint8_t* SectionViewPtr =
            reinterpret_cast<uint8_t*>(_PtrToImageBase) +
            PtrToSectionHeader->PointerToRawData;

        return reinterpret_cast<__Type*>(
            SectionViewPtr + (Rva - PtrToSectionHeader->VirtualAddress)
        );
    }

    bool IsRvaRangeInRelocationTable(uintptr_t Rva, size_t Size) const {
        auto v = _RelocationAddressTable.lower_bound(Rva);
        
        if (v == _RelocationAddressTable.end())
            return false;

        if (v->first == Rva) {
            return true;
        } else {
            auto w = v--;
            if (v->first <= Rva && Rva < v->first + v->second)
                return true;

            if (Rva + Size <= w->first)
                return false;

            return true;
        }
    }
};

