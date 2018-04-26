#include "def.hpp"

namespace std {
#ifdef UNICODE
    typedef wstring Tstring;
#else
    typedef string Tstring;
#endif
}

int _tmain(int argc, TCHAR* argv[]) {
    if (argc != 2 && argc != 3) {
        _tprintf_s(TEXT("Usage:\r\n"));
        _tprintf_s(TEXT("    navicat-patcher.exe <Navicat installation path> [RSA-2048 PEM file]\r\n"));
        return 0;
    }

    {   // check path validity
        DWORD attr = GetFileAttributes(argv[1]);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            _tprintf_s(TEXT("Failed to get installation path attribute. CODE: 0x%08x @[GetFileAttributes]\r\n"), GetLastError());
            return 0;
        }

        if ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            _tprintf_s(TEXT("Error: Path is not a directory.\r\n"));
            return 0;
        }
    }

    std::Tstring navicat_exe_path(argv[1]);
    if (navicat_exe_path.back() != TEXT('/') && navicat_exe_path.back() != TEXT('\\'))
        navicat_exe_path.push_back(TEXT('\\'));
    navicat_exe_path += TEXT("navicat.exe");

    std::Tstring libcc_dll_path(argv[1]);
    if (libcc_dll_path.back() != TEXT('/') && libcc_dll_path.back() != TEXT('\\'))
        libcc_dll_path.push_back(TEXT('\\'));
    libcc_dll_path += TEXT("libcc.dll");

    DWORD NavicatMajorVersion;
    DWORD NavicatMinorVersion;
    if (!patcher::GetNavicatVerion(navicat_exe_path.c_str(), &NavicatMajorVersion, &NavicatMinorVersion))
        return 0;
    
    BOOL status;
    if (NavicatMajorVersion <= 0x000C0000 && NavicatMinorVersion < 0x00190000) {                // for navicat ver < 12.0.25
        status = patcher::Solution0::Do(navicat_exe_path.c_str());
    } else if (NavicatMajorVersion == 0x000C0000 && NavicatMinorVersion == 0x00190000) {        // for navicat ver = 12.0.25
        status = patcher::Solution1::Do(libcc_dll_path.c_str(), argc == 3 ? argv[2] : nullptr);
    } else if (NavicatMajorVersion == 0x000C0000 && NavicatMinorVersion == 0x001A0000) {        // for navicat ver = 12.0.26
        status = patcher::Solution1::Do(libcc_dll_path.c_str(), argc == 3 ? argv[2] : nullptr);
    } else if (NavicatMajorVersion == 0x000C0000 && NavicatMinorVersion == 0x001B0000) {        // for navicat ver = 12.0.27
        status = patcher::Solution1::Do(libcc_dll_path.c_str(), argc == 3 ? argv[2] : nullptr);
    }

    _tprintf_s(TEXT("%s\r\n"), status == TRUE ? TEXT("Success!") : TEXT("Failed!"));
    return 0;
}