#include "ImageInterpreter.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\navicat-patcher\\ImageInterpreter.cpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    ImageInterpreter::ImageInterpreter() :
        _DosHeader(nullptr),
        _NtHeaders(nullptr),
        _SectionHeaderTable(nullptr),
        _VsFixedFileInfo(nullptr) {}

    [[nodiscard]]
    ImageInterpreter ImageInterpreter::ParseImage(PVOID ImageBase, bool DisableRelocationParsing) {
        ImageInterpreter NewImage;

        NewImage._DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
        if (NewImage._DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Invalid Image. (DOS signature check failure)"))
                .AddHint(TEXT("Are you sure you DO provide a valid WinPE file?"));
        }

        NewImage._NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<uint8_t*>(ImageBase) + NewImage._DosHeader->e_lfanew
            );
        if (NewImage._NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Invalid Image. (NT signature check failure)"))
                .AddHint(TEXT("Are you sure you DO provide a valid WinPE file?"));
        }
        
#if defined(_M_AMD64)
        if (NewImage._NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Invalid Image. (Optional header magic check failure)"))
                .AddHint(TEXT("Are you sure you DO provide a valid 64-bits WinPE file?"));
        }
        if (NewImage._NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Invalid Image. (Machine check failure)"))
                .AddHint(TEXT("Are you sure you DO provide a valid 64-bits WinPE file?"));
        }
#elif defined(_M_IX86)
        if (NewImage._NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Invalid Image. (Optional header magic check failure)"))
                .AddHint(TEXT("Are you sure you DO provide a valid 32-bits WinPE file?"));
        }
        if (NewImage._NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Invalid Image. (Machine check failure)"))
                .AddHint(TEXT("Are you sure you DO provide a valid 32-bits WinPE file?"));
        }
#else
#error "Unsupported architecture."
#endif

        NewImage._SectionHeaderTable = reinterpret_cast<PIMAGE_SECTION_HEADER>(
            reinterpret_cast<char*>(&NewImage._NtHeaders->OptionalHeader) + NewImage._NtHeaders->FileHeader.SizeOfOptionalHeader
            );

        for (WORD i = 0; i < NewImage._NtHeaders->FileHeader.NumberOfSections; ++i) {
            uint64_t SectionName = *reinterpret_cast<uint64_t*>(NewImage._SectionHeaderTable[i].Name);

            if (NewImage._SectionNameTable.find(SectionName) == NewImage._SectionNameTable.end()) {
                NewImage._SectionNameTable[SectionName] = i;
            }

            NewImage._SectionAddressTable[NewImage._SectionHeaderTable[i].VirtualAddress] = i;
            NewImage._SectionOffsetTable[NewImage._SectionHeaderTable[i].PointerToRawData] = i;
        }

        if (!DisableRelocationParsing && NewImage._NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
            auto RelocTableRva = NewImage._NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            auto RelocTable = NewImage.RvaToPointer<PIMAGE_BASE_RELOCATION>(RelocTableRva);

            while (RelocTable->VirtualAddress != 0) {
                uintptr_t Rva = RelocTable->VirtualAddress;
                PWORD RelocItems = reinterpret_cast<PWORD>(RelocTable + 1);
                DWORD RelocItemsCount = (RelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                for (DWORD i = 0; i < RelocItemsCount; ++i) {
                    auto RelocType = RelocItems[i] >> 12;

                    switch (RelocType) {
                        case IMAGE_REL_BASED_ABSOLUTE:
                            break;
                        case IMAGE_REL_BASED_HIGH:
                        case IMAGE_REL_BASED_LOW:
                        case IMAGE_REL_BASED_HIGHADJ:
                            NewImage._RelocationAddressTable[Rva + (RelocItems[i] & 0x0fff)] = 2;
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            NewImage._RelocationAddressTable[Rva + (RelocItems[i] & 0x0fff)] = 4;
                            break;
#if defined(IMAGE_REL_BASED_DIR64)
                        case IMAGE_REL_BASED_DIR64:
                            NewImage._RelocationAddressTable[Rva + (RelocItems[i] & 0x0fff)] = 8;
                            break;
#endif
                        default:
                            break;
                    }
                }

                RelocTable = reinterpret_cast<PIMAGE_BASE_RELOCATION>(&RelocItems[RelocItemsCount]);
            }
        }

        if (NewImage._NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) {
            uintptr_t ResourceRva = NewImage._NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;

            auto ResourceTypeTable = 
                NewImage.RvaToPointer<PIMAGE_RESOURCE_DIRECTORY>(ResourceRva);
            auto ResourceTypeNameEntries = 
                reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(ResourceTypeTable + 1);
            auto ResourceTypeIdEntries = 
                ResourceTypeNameEntries + ResourceTypeTable->NumberOfNamedEntries;
            bool VS_FII_Ok = false;

            for (WORD i = 0; i < ResourceTypeTable->NumberOfIdEntries && !VS_FII_Ok; ++i) {
                if (ResourceTypeIdEntries[i].Id == reinterpret_cast<uintptr_t>(RT_VERSION) && ResourceTypeIdEntries[i].DataIsDirectory) {
                    auto ResourceNameTable = 
                        NewImage.RvaToPointer<PIMAGE_RESOURCE_DIRECTORY>(ResourceRva + ResourceTypeIdEntries[i].OffsetToDirectory);
                    auto ResourceNameNameEntries = 
                        reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(ResourceNameTable + 1);
                    auto ResourceNameIdEntries = 
                        ResourceNameNameEntries + ResourceNameTable->NumberOfNamedEntries;

                    for (WORD j = 0; j < ResourceNameTable->NumberOfIdEntries && !VS_FII_Ok; ++j) {
                        if (ResourceNameIdEntries[j].Id == VS_VERSION_INFO && ResourceNameIdEntries[j].DataIsDirectory) {
                            auto ResourceLangTable = 
                                NewImage.RvaToPointer<PIMAGE_RESOURCE_DIRECTORY>(ResourceRva + ResourceNameIdEntries[j].OffsetToDirectory);
                            auto ResourceLangNameEntries =
                                reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(ResourceLangTable + 1);
                            auto ResourceLangIdEntries =
                                ResourceLangNameEntries + ResourceLangTable->NumberOfNamedEntries;
                            
                            for (WORD k = 0; k < ResourceLangTable->NumberOfIdEntries && !VS_FII_Ok; ++k) {
                                if (ResourceLangIdEntries[k].Id == MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL) && !ResourceLangIdEntries[k].DataIsDirectory) {
                                    auto ResourceDataEntry =
                                        NewImage.RvaToPointer<PIMAGE_RESOURCE_DATA_ENTRY>(ResourceRva + ResourceLangIdEntries[k].OffsetToData);

                                    auto VsVersionInfo = NewImage.RvaToPointer<PBYTE>(ResourceDataEntry->OffsetToData);
                                    auto VsVersionInfoszKey = reinterpret_cast<PWSTR>(VsVersionInfo + 6);
                                    if (_wcsicmp(VsVersionInfoszKey, L"VS_VERSION_INFO") == 0) {
                                        auto p = reinterpret_cast<PBYTE>(VsVersionInfoszKey + _countof(L"VS_VERSION_INFO"));
                                        while (NewImage.PointerToRva(p) % sizeof(DWORD)) {
                                            ++p;
                                        }

                                        if (reinterpret_cast<VS_FIXEDFILEINFO*>(p)->dwSignature == VS_FFI_SIGNATURE) {
                                            NewImage._VsFixedFileInfo = reinterpret_cast<VS_FIXEDFILEINFO*>(p);
                                            VS_FII_Ok = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return NewImage;
    }

    [[nodiscard]]
    PIMAGE_DOS_HEADER ImageInterpreter::ImageDosHeader() const noexcept {
        return _DosHeader;
    }

    [[nodiscard]]
    PIMAGE_NT_HEADERS ImageInterpreter::ImageNtHeaders() const noexcept {
        return _NtHeaders;
    }

    [[nodiscard]]
    PIMAGE_SECTION_HEADER ImageInterpreter::ImageSectionTable() const noexcept {
        return _SectionHeaderTable;
    }

    [[nodiscard]]
    PIMAGE_SECTION_HEADER ImageInterpreter::ImageSectionHeader(PCSTR lpszSectionName) const {
        uint64_t NameValue = 0;

        for (int i = 0; i < sizeof(NameValue) && lpszSectionName[i]; ++i)
            reinterpret_cast<PSTR>(&NameValue)[i] = lpszSectionName[i];

        auto it = _SectionNameTable.find(NameValue);

        if (it == _SectionNameTable.end()) {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Target section header is not found."))
                .AddHint(std::xstring::format(TEXT("lpszSectionName = %s"), lpszSectionName));
        }

        return &_SectionHeaderTable[it->second];
    }

    [[nodiscard]]
    PIMAGE_SECTION_HEADER ImageInterpreter::ImageSectionHeader(uintptr_t Rva) const {
        auto it = _SectionAddressTable.upper_bound(Rva);
        if (it != _SectionAddressTable.begin()) {
            --it;
        }

        auto SectionHeader = &_SectionHeaderTable[it->second];
        uintptr_t SectionRvaBegin = SectionHeader->VirtualAddress;
        uintptr_t SectionRvaEnd = SectionRvaBegin + SectionHeader->Misc.VirtualSize;

        if (SectionRvaBegin <= Rva && Rva < SectionRvaEnd) {
            return SectionHeader;
        } else {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Target section header is not found."))
                .AddHint(std::xstring::format(TEXT("Rva = 0x%zx"), Rva));
        }
    }

    [[nodiscard]]
    uintptr_t ImageInterpreter::RvaToFileOffset(uintptr_t Rva) const {
        auto SectionHeader = ImageSectionHeader(Rva);
        return SectionHeader->PointerToRawData + (Rva - static_cast<uintptr_t>(SectionHeader->VirtualAddress));
    }

    [[nodiscard]]
    uintptr_t ImageInterpreter::FileOffsetToRva(uintptr_t FileOffset) const {
        auto it = _SectionOffsetTable.upper_bound(FileOffset);
        if (it != _SectionOffsetTable.begin()) {
            --it;
        }

        auto SectionHeader = &_SectionHeaderTable[it->second];
        uintptr_t SectionFileOffsetBegin = SectionHeader->PointerToRawData;
        uintptr_t SectionFileOffsetEnd = SectionFileOffsetBegin + SectionHeader->SizeOfRawData;

        if (SectionFileOffsetBegin <= FileOffset && FileOffset < SectionFileOffsetEnd) {
            return SectionHeader->VirtualAddress + (FileOffset - SectionHeader->PointerToRawData);
        } else {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Target section header is not found."))
                .AddHint(std::xstring::format(TEXT("FileOffset = 0x%zx"), FileOffset));
        }
    }

    [[nodiscard]]
    bool ImageInterpreter::IsRvaRangeInRelocTable(uintptr_t Rva, size_t Size) const {
        auto it = _RelocationAddressTable.upper_bound(Rva);
        if (it != _RelocationAddressTable.begin()) {
            --it;
        }

        return it->first <= Rva && Rva < it->first + it->second;
    }

    DWORD ImageInterpreter::ImageFileMajorVersion() const {
        if (_VsFixedFileInfo) {
            return _VsFixedFileInfo->dwFileVersionMS;
        } else {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Image does not have version info."));
        }
    }

    DWORD ImageInterpreter::ImageFileMinorVersion() const {
        if (_VsFixedFileInfo) {
            return _VsFixedFileInfo->dwFileVersionLS;
        } else {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Image does not have version info."));
        }
    }

    DWORD ImageInterpreter::ImageProductMajorVersion() const {
        if (_VsFixedFileInfo) {
            return _VsFixedFileInfo->dwProductVersionMS;
        } else {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Image does not have version info."));
        }
    }

    DWORD ImageInterpreter::ImageProductMinorVersion() const {
        if (_VsFixedFileInfo) {
            return _VsFixedFileInfo->dwProductVersionLS;
        } else {
            throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Image does not have version info."));
        }
    }
}

