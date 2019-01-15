#pragma once
#include <windows.h>
#include <string>

#include "ExceptionSystem.hpp"
#include "ResourceGuardWin32.hpp"

#if defined(UNICODE) || defined(_UNICODE)
using String = std::wstring;
#else
using String = std::string;
#endif

class FileMapper {
private:
    ResourceGuard<FileHandleTraits> _FileHandle;
    ResourceGuard<GenericHandleTraits> _FileMapHandle;
    ResourceGuard<MapViewTraits> _FileView;
public:

    static bool IsExist(const String&& FilePath) {
        DWORD dwAttr = GetFileAttributes(FilePath.c_str());
        if (dwAttr == INVALID_FILE_ATTRIBUTES) {
            if (GetLastError() == ERROR_FILE_NOT_FOUND)
                return false;
            else
                throw SystemError(__BASE_FILE__, __LINE__, GetLastError(),
                                  "GetFileAttributes fails.");
        } else {
            return (dwAttr & FILE_ATTRIBUTE_DIRECTORY) == 0;
        }
    }

    template<typename _Type>
    _Type* GetView() const noexcept {
        return reinterpret_cast<_Type*>(_FileView.GetHandle());
    }

    void MapFile(const String& FileName) {
        ResourceGuard<FileHandleTraits> TempFileHandle;
        ResourceGuard<GenericHandleTraits> TempFileMapHandle;
        ResourceGuard<MapViewTraits> TempFileView;

        TempFileHandle.TakeHoldOf(
            CreateFile(FileName.c_str(),
                       GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL)
        );
        if (TempFileHandle.IsValid() == false)
            throw SystemError(__BASE_FILE__, __LINE__, GetLastError(),
                              "CreateFile fails.");

        TempFileMapHandle.TakeHoldOf(
            CreateFileMapping(TempFileHandle,
                              NULL,
                              PAGE_READWRITE,
                              0,
                              0,
                              NULL)
        );
        if (TempFileMapHandle.IsValid() == false)
            throw SystemError(__BASE_FILE__, __LINE__, GetLastError(),
                              "CreateFileMapping fails.");

        TempFileView.TakeHoldOf(
            MapViewOfFile(TempFileMapHandle,
                          FILE_MAP_READ | FILE_MAP_WRITE,
                          0,
                          0,
                          0)
        );
        if (TempFileView.IsValid() == false)
            throw SystemError(__BASE_FILE__, __LINE__, GetLastError(),
                              "MapViewOfFile fails.");

        _FileView.Release();
        _FileView = std::move(TempFileView);
        _FileMapHandle.Release();
        _FileMapHandle = std::move(TempFileMapHandle);
        _FileHandle.Release();
        _FileHandle = std::move(TempFileHandle);
    }

    void Release() {
        _FileView.Release();
        _FileMapHandle.Release();
        _FileHandle.Release();
    }
};


