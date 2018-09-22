#include <iostream>
#include "RSACipher.hpp"

namespace Helper {
    bool ConvertToUTF8(std::string& str);
}

#define MODE_SIMPLE     1
#define MODE_ADVANCED   2
#define FLAG_BIN        1
#define FLAG_TEXT       2
void Process(RSACipher* cipher, int mode, int flag);

void help() {
    std::cout << "Usage:" << std::endl;
    std::cout << "    navicat-keygen.exe <-bin|-text> [-adv] <RSA-2048 PrivateKey(PEM file)>" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 3 && argc != 4) {
        help();
        return 0;
    }
    
    std::string RSAPrivateKeyPath = argv[argc - 1];
    RSACipher* cipher = nullptr;

    cipher = RSACipher::Create();
    if (cipher == nullptr) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: Failed to create RSACipher." << std::endl;
        goto ON_tmain_ERROR;
    }

    if (!Helper::ConvertToUTF8(RSAPrivateKeyPath)) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: ConvertToUTF8 fails." << std::endl;
        goto ON_tmain_ERROR;
    }

    if (!cipher->ImportKeyFromFile<RSACipher::KeyType::PrivateKey>(RSAPrivateKeyPath)) {
        std::cout << "@Function: " << __FUNCSIG__ << " LINE: " << __LINE__ << std::endl;
        std::cout << "ERROR: ImportKeyFromFile<RSACipher::KeyType::PrivateKey> fails." << std::endl;
        goto ON_tmain_ERROR;
    }

    if (argc == 3) {
        if (_stricmp(argv[1], "-bin") == 0)
            Process(cipher, MODE_SIMPLE, FLAG_BIN);
        else if (_stricmp(argv[1], "-text") == 0)
            Process(cipher, MODE_SIMPLE, FLAG_TEXT);
        else
            help();
    }

    if (argc == 4) {
        if (_stricmp(argv[1], "-bin") == 0)
            Process(cipher, MODE_ADVANCED, FLAG_BIN);
        else if (_stricmp(argv[1], "-text") == 0)
            Process(cipher, MODE_ADVANCED, FLAG_TEXT);
        else
            help();
    }

ON_tmain_ERROR:
    if (cipher)
        delete cipher;
    return 0;
}
