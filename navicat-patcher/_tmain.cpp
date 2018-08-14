#include "def.hpp"

bool ConvertToUTF8(LPCSTR from, std::string& to) {
    bool bSuccess = false;
    int len = 0;
    LPWSTR lpUnicodeString = nullptr;

    len = MultiByteToWideChar(CP_ACP, NULL, from, -1, NULL, 0);
    if (len == 0)
        goto ON_ConvertToUTF8_0_ERROR;

    lpUnicodeString = reinterpret_cast<LPWSTR>(HeapAlloc(GetProcessHeap(),
                                                         HEAP_ZERO_MEMORY,
                                                         len * sizeof(WCHAR)));
    if (lpUnicodeString == nullptr)
        goto ON_ConvertToUTF8_0_ERROR;

    if (!MultiByteToWideChar(CP_ACP, NULL, from, -1, lpUnicodeString, len))
        goto ON_ConvertToUTF8_0_ERROR;

    len = WideCharToMultiByte(CP_UTF8, NULL, lpUnicodeString, -1, NULL, 0, NULL, NULL);
    if (len == 0)
        goto ON_ConvertToUTF8_0_ERROR;

    to.resize(len);
    if (!WideCharToMultiByte(CP_UTF8, NULL, lpUnicodeString, -1, to.data(), len, NULL, NULL))
        goto ON_ConvertToUTF8_0_ERROR;

    while (to.back() == 0)
        to.pop_back();

    bSuccess = true;

ON_ConvertToUTF8_0_ERROR:
    if (lpUnicodeString)
        HeapFree(GetProcessHeap(), NULL, lpUnicodeString);
    return bSuccess;
}

bool ConvertToUTF8(LPCWSTR from, std::string& to) {
    bool bSuccess = false;
    int len = 0;

    len = WideCharToMultiByte(CP_UTF8, NULL, from, -1, NULL, 0, NULL, NULL);
    if (len == 0)
        goto ON_ConvertToUTF8_1_ERROR;

    to.resize(len);
    if (!WideCharToMultiByte(CP_UTF8, NULL, from, -1, to.data(), len, NULL, NULL))
        goto ON_ConvertToUTF8_1_ERROR;

    while (to.back() == 0)
        to.pop_back();

    bSuccess = true;

ON_ConvertToUTF8_1_ERROR:
    return bSuccess;
}

bool ConvertToUTF8(std::string& str) {
    bool bSuccess = false;

    std::string temp;
    bSuccess = ConvertToUTF8(str.c_str(), temp);
    if (!bSuccess)
        return false;

    str = temp;
    return true;
}

int _tmain(int argc, TCHAR* argv[]) {
    if (argc != 2 && argc != 3) {
        _tprintf_s(TEXT("Usage:\n"));
        _tprintf_s(TEXT("    navicat-patcher.exe <Navicat installation path> [RSA-2048 PEM file]\n"));
        return 0;
    }

    RSACipher* cipher = NULL;

    cipher = RSACipher::Create();
    if (cipher == NULL) {
        _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
        _tprintf_s(TEXT("RSACipher::Create failed.\n"));
        goto ON_tmain_ERROR;
    }

    if (!patcher::Solution0::Init(argv[1]))
        goto ON_tmain_ERROR;
    if (!patcher::Solution1::Init(argv[1]))
        goto ON_tmain_ERROR;

    if (argc == 3) {
        std::string PrivateKeyFileName;

        if (!ConvertToUTF8(argv[2], PrivateKeyFileName)) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: ConvertToUTF8 failed.\n"));
            goto ON_tmain_ERROR;
        }

        if (!cipher->ImportKeyFromFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::PEM>(PrivateKeyFileName)) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: cipher->ImportKeyFromFile failed.\n"));
            goto ON_tmain_ERROR;
        }

        if (patcher::Solution0::CheckKey(cipher) == FALSE || patcher::Solution1::CheckKey(cipher) == FALSE) {
            _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
            _tprintf_s(TEXT("ERROR: RSA private key specified cannot be used.\n"));
            goto ON_tmain_ERROR;
        }
    } else {
        do {
            cipher->GenerateKey(2048);
        } while (patcher::Solution0::CheckKey(cipher) && patcher::Solution1::CheckKey(cipher));
        cipher->ExportKeyToFile<RSACipher::KeyType::PrivateKey, RSACipher::KeyFormat::PEM>("RegPrivateKey.pem");
        _tprintf_s(TEXT("New RSA private key has been saved to RegPrivateKey.pem.\n"));
    }

    // ------------------
    // begin Solution0
    // ------------------
    if (!patcher::Solution0::FindTargetFile()) {
        _tprintf_s(TEXT("@%s LINE: %u\n"), TEXT(__FUNCTION__), __LINE__);
        _tprintf_s(TEXT("ERROR: Cannot find main program. Are you sure the path you specified is correct?\n"));
        goto ON_tmain_ERROR;
    }

    if (!patcher::Solution0::CheckFile()) 
        goto ON_tmain_ERROR;

    if (!patcher::Solution0::BackupFile())
        goto ON_tmain_ERROR;

    if (!patcher::Solution0::Do(cipher))
        goto ON_tmain_ERROR;
    
    _tprintf_s(TEXT("Solution0 has been done successfully.\n"));
    _tprintf_s(TEXT("\n"));

    // ------------------
    // begin Solution1
    // ------------------
    if (!patcher::Solution1::FindTargetFile())
        goto ON_tmain_ERROR;

    if (!patcher::Solution1::FindOffset())
        goto ON_tmain_ERROR;

    if (!patcher::Solution1::BackupFile())
        goto ON_tmain_ERROR;

    if (!patcher::Solution1::Do(cipher))
        goto ON_tmain_ERROR;

    _tprintf_s(TEXT("Solution1 has been done successfully.\n"));
    _tprintf_s(TEXT("\n"));

ON_tmain_ERROR:
    patcher::Solution1::Finalize();
    patcher::Solution0::Finalize();
    delete cipher;
    return 0;
}