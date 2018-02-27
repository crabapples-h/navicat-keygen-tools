#include <tchar.h>
#include <windows.h>

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#pragma comment(lib, "libcrypto.lib")

BOOL BackupNavicat(PTSTR NavicatFileName) {
    TCHAR new_NavicatFileName[1024] = { };

    if (NavicatFileName == nullptr)
        NavicatFileName = TEXT("navicat.exe");

    _stprintf_s(new_NavicatFileName, TEXT("%s%s"), NavicatFileName, TEXT(".backup"));

    if (!CopyFile(NavicatFileName, new_NavicatFileName, TRUE)) {
        switch (GetLastError()) {
            case ERROR_FILE_NOT_FOUND:
                _tprintf_s(TEXT("Cannot find %s.\r\n"), NavicatFileName);
                break;
            case ERROR_FILE_EXISTS:
                _tprintf_s(TEXT("Backup file already exists.\r\n"));
                break;
            default:
                _tprintf_s(TEXT("Unknown error. CODE: 0x%08x.\r\n"), GetLastError());
        }
        return FALSE;
    }

    _tprintf_s(TEXT("%s has been backed up.\r\n"), NavicatFileName);
    return TRUE;
}

BOOL ReplaceNavicatPublicKey(HANDLE resUpdater, void* pemPublicKey, size_t length) {
    return UpdateResource(resUpdater,
                          RT_RCDATA,
                          TEXT("ACTIVATIONPUBKEY"),
                          MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                          pemPublicKey, length);
}

RSA* GeneratePrivateKey() {
    RSA* PrivateKey = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    BIO* PrivateKeyFile = BIO_new(BIO_s_file());
    BIO_write_filename(PrivateKeyFile, "RegPrivateKey.pem");
    PEM_write_bio_RSAPrivateKey(PrivateKeyFile, PrivateKey, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free_all(PrivateKeyFile);

    return PrivateKey;
}

int _tmain(int argc, TCHAR* argv[]) {
    if (argc != 2 && argc != 3) {
        _tprintf_s(TEXT("Usage:\r\n"));
        _tprintf_s(TEXT("    navicat-patcher.exe <navicat.exe path>\r\n"));
        return 0;
    }

    if (BackupNavicat(argv[1]) == FALSE)
        return GetLastError();

    RSA* PrivateKey = GeneratePrivateKey();

    HANDLE hUpdater = BeginUpdateResource(argv[1], FALSE);
    if (hUpdater == NULL) {
        _tprintf_s(TEXT("Cannot open file. CODE: 0x%08x\r\n"), GetLastError());
        RSA_free(PrivateKey);
        return GetLastError();
    }

    char pemPublicKey[1024] = { };
    {
        char temp_buf[1024] = { };
        BIO* BIO_pemPublicKey = BIO_new(BIO_s_mem());

        PEM_write_bio_RSA_PUBKEY(BIO_pemPublicKey, PrivateKey);
        BIO_read(BIO_pemPublicKey, temp_buf, 1024);
        BIO_free_all(BIO_pemPublicKey);

        char* pemPublicKey_ptr = pemPublicKey;
        for (size_t i = 0; i < 1024; ++i) {
            if (temp_buf[i] == '\n')
                *(pemPublicKey_ptr++) = '\r';
            if (temp_buf[i] == 0)
                break;
            *(pemPublicKey_ptr++) = temp_buf[i];
        }
    }

    if (ReplaceNavicatPublicKey(hUpdater, pemPublicKey, strlen(pemPublicKey)) == FALSE) {
        _tprintf_s(TEXT("Cannot replace public key. CODE: 0x%08x\r\n"), GetLastError());
        EndUpdateResource(hUpdater, TRUE);
        return GetLastError();
    } else {
        _tprintf_s(TEXT("Public key has been replaced.\r\n"));
        EndUpdateResource(hUpdater, FALSE);
    }

    _tprintf_s(TEXT("Success!\r\n"));
    RSA_free(PrivateKey);
    return 0;
}