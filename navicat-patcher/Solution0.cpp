#include "def.hpp"

// Solution0 is for navicat premium of which the version < 12.0.25
namespace patcher::Solution0 {

    BOOL Do(LPCTSTR navicat_exe_path) {
        if (!BackupFile(navicat_exe_path))
            return FALSE;

        RSA* PrivateKey = GenerateRSAKey();
        if (PrivateKey == nullptr)
            return FALSE;

        if (!WriteRSAPrivateKeyToFile(TEXT("RegPrivateKey.pem"), PrivateKey))
            return FALSE;

        char* pem_pubkey = GetPEMText(PrivateKey);
        if (pem_pubkey == nullptr)
            return FALSE;

        RSA_free(PrivateKey);   // we do not need it anymore

        HANDLE hUpdater = BeginUpdateResource(navicat_exe_path, FALSE);
        if (hUpdater == NULL) {
            _tprintf_s(TEXT("Cannot modify navicat.exe. CODE: 0x%08x @[patcher::Solution0::Do -> BeginUpdateResource]\r\n"), GetLastError());

            delete[] pem_pubkey;
            return FALSE;
        }

        if (!UpdateResource(hUpdater,
                            RT_RCDATA,
                            TEXT("ACTIVATIONPUBKEY"),
                            MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                            pem_pubkey, strlen(pem_pubkey))) {
            _tprintf_s(TEXT("Cannot replace public key. CODE: 0x%08x @[patcher::Solution0::Do -> UpdateResource]\r\n"), GetLastError());

            EndUpdateResource(hUpdater, TRUE);
            delete[] pem_pubkey;
            return FALSE;
        } else {
            _tprintf_s(TEXT("@[patcher::Solution0::Do]: Public key has been replaced.\r\n"));

            EndUpdateResource(hUpdater, FALSE);
            delete[] pem_pubkey;
            return TRUE;
        }
    }

}