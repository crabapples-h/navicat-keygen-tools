#pragma once
#include <tchar.h>
#include <windows.h>
#include <string>
#include "RSACipher.hpp"

#ifdef UNICODE
namespace std { typedef wstring Tstring; }
#else
namespace std { typedef string Tstring; }
#endif

namespace Helper {
    std::string EncryptPublicKey(const std::string& PublicKeyString);

    bool ConvertToUTF8(LPCSTR from, std::string& to);
    bool ConvertToUTF8(LPCWSTR from, std::string& to);
    bool ConvertToUTF8(std::string& str);

    void ErrorReport(LPCTSTR at, UINT line, LPCTSTR msg);
    void ErrorReport(LPCTSTR at, UINT line, LPCTSTR msg, DWORD err_code);

    //
    //  Print memory data in [from, to) at least
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must >= `from`
    //  
    void PrintMemory(const void* from, const void* to, const void* base = nullptr);

    PIMAGE_SECTION_HEADER ImageSectionHeader(PVOID lpBase, LPCSTR lpSectionName);

    template<typename _Type, bool _Ascending = true>
    void QuickSort(_Type* pArray, off_t begin, off_t end) {
        if (end - begin <= 1)
            return;

        off_t i = begin;
        off_t j = end - 1;
        _Type seperator = static_cast<_Type&&>(pArray[begin]);

        while (i < j) {
            if (_Ascending) {
                while (i < j && seperator <= pArray[j])
                    --j;

                if (i < j)
                    pArray[i++] = static_cast<_Type&&>(pArray[j]);

                while (i < j && pArray[i] <= seperator)
                    ++i;

                if (i < j)
                    pArray[j--] = static_cast<_Type&&>(pArray[i]);
            } else {
                while (i < j && seperator >= pArray[j])
                    --j;

                if (i < j)
                    pArray[i++] = static_cast<_Type&&>(pArray[j]);

                while (i < j && pArray[i] >= seperator)
                    ++i;

                if (i < j)
                    pArray[j--] = static_cast<_Type&&>(pArray[i]);
            }
        }

        pArray[i] = static_cast<_Type&&>(seperator);
        QuickSort<_Type, _Ascending>(pArray, begin, i);
        QuickSort<_Type, _Ascending>(pArray, i + 1, end);
    }
}

#define REPORT_ERROR(msg) Helper::ErrorReport(TEXT(__FUNCTION__), __LINE__, TEXT(msg))
#define REPORT_ERROR_WITH_CODE(msg, err_code) Helper::ErrorReport(TEXT(__FUNCTION__), __LINE__, TEXT(msg), (err_code))

#define PRINT_MESSAGE(msg) _tprintf_s(TEXT("%s\n"), TEXT(msg))
#define PRINT_LPCTSTR(msg) _tprintf_s(TEXT("%s\n"), (msg))
#define PRINT_LPCSTR(msg) printf_s("%s\n", (msg))
#define PRINT_LPCWSTR(msg) wprintf_s(L"%s\n", (msg))

template<HANDLE __Invalid>
class HandleGuard {
private:
    bool bError;
    HANDLE& Handle;
public:
    HandleGuard(HANDLE& Target) noexcept : bError(true), Handle(Target) {}
    void ErrorOccurs() noexcept { bError = true; }
    void NoErrorOccurs() noexcept { bError = false; }
    ~HandleGuard() noexcept {
        if (bError && Handle != __Invalid) {
            CloseHandle(Handle);
            Handle = __Invalid;
        }
    }
};

class FileMapper {
private:
    HANDLE hFile;
    HANDLE hMap;
    PVOID pMapView;
public:
    FileMapper() noexcept :
        hFile(INVALID_HANDLE_VALUE),
        hMap(NULL),
        pMapView(nullptr) {}

    void Release() noexcept {
        if (pMapView) {
            UnmapViewOfFile(pMapView);
            pMapView = NULL;
        }

        if (hMap) {
            CloseHandle(hMap);
            hMap = NULL;
        }

        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
    }

    template<typename _Type>
    _Type* GetView() const noexcept {
        return reinterpret_cast<_Type*>(pMapView);
    }

    DWORD MapFile(std::Tstring& Name) noexcept {
        HandleGuard<INVALID_HANDLE_VALUE> hFileGuard(hFile);
        HandleGuard<NULL> hMapGuard(hMap);

        hFile = CreateFile(Name.c_str(),
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ,    // share read so that we can copy
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return GetLastError();

        hMap = CreateFileMapping(hFile,
                                 NULL,
                                 PAGE_READWRITE,
                                 0,
                                 0,
                                 NULL);
        if (hMap == NULL)
            return GetLastError();

        pMapView = MapViewOfFile(hMap,
                                 FILE_MAP_READ | FILE_MAP_WRITE,
                                 0,
                                 0,
                                 0);
        if (pMapView == NULL)
            return GetLastError();

        hFileGuard.NoErrorOccurs();
        hMapGuard.NoErrorOccurs();
        return ERROR_SUCCESS;
    }

    ~FileMapper() {
        Release();
    }
};

namespace Patcher {

    class Solution {
    public:
        virtual void SetFile(FileMapper* pFile) = 0;
        virtual bool CheckKey(RSACipher* cipher) const = 0;
        virtual bool FindPatchOffset() = 0;
        virtual bool MakePatch(RSACipher* cipher) const = 0;
        virtual ~Solution() {}
    };

}
