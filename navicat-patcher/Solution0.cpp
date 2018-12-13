#include "def.hpp"

// The following APIs are in version.lib
// GetFileVersionInfoSize
// GetFileVersionInfo
// VerQueryValue
// #pragma comment(lib, "version.lib")     

namespace Patcher {

    const char Solution0::Keyword[461] =
        "-----BEGIN PUBLIC KEY-----\r\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I\r\n"
        "qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv\r\n"
        "a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF\r\n"
        "R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2\r\n"
        "WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt\r\n"
        "YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ\r\n"
        "awIDAQAB\r\n"
        "-----END PUBLIC KEY-----\r\n";

    bool Solution0::FindPatchOffset() noexcept {
        bool bFound = false;

        PIMAGE_SECTION_HEADER pResourceSection =
            Helper::ImageSectionHeader(pTargetFile->GetView<uint8_t>(), ".rsrc");
        
        if (pResourceSection == nullptr)
            return false;
        
        uint8_t* pResourceSectionData =
            pTargetFile->GetView<uint8_t>() + pResourceSection->PointerToRawData;
        
        for (DWORD i = 0; i < pResourceSection->SizeOfRawData; ++i) {
            if (memcmp(pResourceSectionData + i, Keyword, KeywordLength) == 0) {
                PatchOffset = pResourceSection->PointerToRawData + i;
                bFound = true;
                break;
            }
        }

        if (bFound)
            _tprintf_s(TEXT("MESSAGE: [Solution0] Keyword has been found: offset = +0x%08lx.\n"), PatchOffset);
        return bFound;
    }

    bool Solution0::MakePatch(RSACipher* cipher) const {
        uint8_t* lpTargetFileView = pTargetFile->GetView<uint8_t>();
        std::string RSAPublicKeyPEM;

        RSAPublicKeyPEM = 
            cipher->ExportKeyString<RSACipher::KeyType::PublicKey, RSACipher::KeyFormat::PEM>();
        if (RSAPublicKeyPEM.empty()) {
            REPORT_ERROR("ERROR: cipher->ExportKeyString failed.");
            return false;
        }

        // lambda function, replace '\n' to '\r\n'
        [](std::string& str, const std::string& OldSub, const std::string& NewSub) {
            std::string::size_type pos = 0;
            std::string::size_type srclen = OldSub.size();
            std::string::size_type dstlen = NewSub.size();

            while ((pos = str.find(OldSub, pos)) != std::string::npos) {
                str.replace(pos, srclen, NewSub);
                pos += dstlen;
            }
        } (RSAPublicKeyPEM, "\n", "\r\n");

        if (RSAPublicKeyPEM.length() != KeywordLength) {
            REPORT_ERROR("ERROR: Public key length does not match.");
            return false;
        }

        PRINT_MESSAGE("//");
        PRINT_MESSAGE("// Begin Solution0");
        PRINT_MESSAGE("//");
        _tprintf_s(TEXT("@+0x%08X\nPrevious:\n"), PatchOffset);
        Helper::PrintMemory(lpTargetFileView + PatchOffset,
                            lpTargetFileView + PatchOffset + KeywordLength, 
                            lpTargetFileView);

        memcpy(lpTargetFileView + PatchOffset, RSAPublicKeyPEM.c_str(), KeywordLength);

        PRINT_MESSAGE("After:");
        Helper::PrintMemory(lpTargetFileView + PatchOffset,
                            lpTargetFileView + PatchOffset + KeywordLength,
                            lpTargetFileView);
        PRINT_MESSAGE("");
        
        return true;
    }

//     DWORD Solution0::GetMainAppVersion(LPDWORD lpMajorVer, LPDWORD lpMinorVer) {
//         BOOL bSuccess = FALSE;
//         DWORD dwLastError = ERROR_SUCCESS;
//         std::Tstring TargetFileFullName = InstallationPath + MainAppName;
// 
//         DWORD dwSize = 0;
//         PVOID lpData = NULL;
//         VS_FIXEDFILEINFO* lpVersionInfo = NULL;
//         UINT VersionInfoSize = 0;
// 
//         dwSize = GetFileVersionInfoSize(TargetFileFullName.c_str(), 
//                                         &dwSize);   // MSDN doesn't say it can be NULL.
//                                                     // so I use dwSize to receive this deprecated value
//         if (dwSize == 0) {
//             dwLastError = GetLastError();
//             REPORT_ERROR_WITH_CODE("ERROR: GetFileVersionInfoSize failed.", dwLastError);
//             goto ON_Solution0_GetMainAppVersion_ERROR;
//         }
// 
//         lpData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
//         if (lpData == nullptr) {
//             dwLastError = GetLastError();
//             REPORT_ERROR_WITH_CODE("ERROR: HeapAlloc failed.", dwLastError);
//             goto ON_Solution0_GetMainAppVersion_ERROR;
//         }
// 
//         if (!GetFileVersionInfo(TargetFileFullName.c_str(), NULL, dwSize, lpData)) {
//             dwLastError = GetLastError();
//             REPORT_ERROR_WITH_CODE("ERROR: GetFileVersionInfo failed.", dwLastError);
//             goto ON_Solution0_GetMainAppVersion_ERROR;
//         }
// 
//         if (!VerQueryValue(lpData, TEXT("\\"), reinterpret_cast<LPVOID*>(&lpVersionInfo), &VersionInfoSize)) {
//             dwLastError = GetLastError();
//             REPORT_ERROR_WITH_CODE("ERROR: VerQueryValue failed.", dwLastError);
//             goto ON_Solution0_GetMainAppVersion_ERROR;
//         }
// 
//         *lpMajorVer = lpVersionInfo->dwProductVersionMS;
//         *lpMinorVer = lpVersionInfo->dwProductVersionLS;
// 
//         bSuccess = TRUE;
//     ON_Solution0_GetMainAppVersion_ERROR:
//         if (lpData)
//             HeapFree(GetProcessHeap(), NULL, lpData);
//         return bSuccess;
//     }
    
}
