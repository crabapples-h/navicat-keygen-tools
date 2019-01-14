#pragma once
#include <type_traits>
#include <windows.h>

inline
PIMAGE_DOS_HEADER GetImageDosHeader(PVOID pImageBase) {
    return reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
}

inline
PIMAGE_NT_HEADERS GetImageNtHeaders(PVOID pImageBase) {
    char* pImageBytes = reinterpret_cast<char*>(pImageBase);
    return reinterpret_cast<PIMAGE_NT_HEADERS>(
        pImageBytes + GetImageDosHeader(pImageBase)->e_lfanew
    );
}

inline
PIMAGE_FILE_HEADER GetImageCoffHeader(PVOID pImageBase) {
    return &GetImageNtHeaders(pImageBase)->FileHeader;
}

inline
PIMAGE_OPTIONAL_HEADER GetImageOptionalHeader(PVOID pImageBase) {
    return &GetImageNtHeaders(pImageBase)->OptionalHeader;
}

inline
PIMAGE_SECTION_HEADER GetSectionHeaderList(PVOID pImageBase) {
    return
        reinterpret_cast<PIMAGE_SECTION_HEADER>(
            reinterpret_cast<char*>(&GetImageNtHeaders(pImageBase)->OptionalHeader) +
            GetImageNtHeaders(pImageBase)->FileHeader.SizeOfOptionalHeader
        );
}

inline
PIMAGE_SECTION_HEADER GetSectionHeaderByName(PVOID pImageBase, LPCSTR lpSectionName) {
    PIMAGE_NT_HEADERS pNtHeader = GetImageNtHeaders(pImageBase);
    PIMAGE_SECTION_HEADER pSectionHeaders = GetSectionHeaderList(pImageBase);

    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
        if (_stricmp(reinterpret_cast<char*>(pSectionHeaders[i].Name), lpSectionName) == 0)
            return &pSectionHeaders[i];

    return NULL;
}

inline
PIMAGE_SECTION_HEADER GetSectionHeaderFromRva(SIZE_T Rva, PVOID pImageBase) {
    PIMAGE_NT_HEADERS pNtHeader = GetImageNtHeaders(pImageBase);
    PIMAGE_SECTION_HEADER pSectionHeaderList = GetSectionHeaderList(pImageBase);
    for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i) {
        if (pSectionHeaderList[i].VirtualAddress <= Rva && 
            Rva < pSectionHeaderList[i].VirtualAddress + pSectionHeaderList[i].SizeOfRawData) 
        {
            return &pSectionHeaderList[i];
        }
    }
    return NULL;
}

inline 
bool IsRvaInSection(SIZE_T Rva, PIMAGE_SECTION_HEADER pSectionHeader) {
    if (pSectionHeader->VirtualAddress <= Rva &&
        Rva < pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData) 
    {
        return true;
    } else {
        return false;
    }
}

template<typename __ReturnType = PVOID>
__ReturnType RvaToPointer(SIZE_T Rva, PVOID pImageBase, PIMAGE_SECTION_HEADER pHintSection = NULL) {
    static_assert(std::is_pointer<__ReturnType>::value);
    if (pHintSection == NULL || IsRvaInSection(Rva, pHintSection) == false)
        pHintSection = GetSectionHeaderFromRva(Rva, pImageBase);

    if (pHintSection == NULL) {
        return NULL;
    } else {
        PIMAGE_NT_HEADERS pNtHeader = GetImageNtHeaders(pImageBase);
        return reinterpret_cast<__ReturnType>(
            reinterpret_cast<char*>(pImageBase) + pHintSection->PointerToRawData +
            (Rva - pHintSection->VirtualAddress)
        );
    }
}

