#pragma once
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <string>

#ifdef _DEBUG
#pragma comment(lib, "libcryptoMTd.lib")
#else
#pragma comment(lib, "libcryptoMT.lib")
#endif
#pragma comment(lib, "WS2_32.lib")      // some symbol are used in OpenSSL static lib
#pragma comment(lib, "Crypt32.lib")     // some symbol are used in OpenSSL static lib

class RSACipher {
private:
    RSA * _RsaObj;

    RSACipher() : _RsaObj(nullptr) {}
    RSACipher(RSA* lpRsa) : _RsaObj(lpRsa) {}

    RSACipher(const RSACipher&) = delete;
    RSACipher(RSACipher&&) = delete;
    RSACipher& operator=(const RSACipher&) = delete;
    RSACipher& operator=(RSACipher&&) = delete;

public:

    enum class KeyType {
        PrivateKey,
        PublicKey
    };

    enum class KeyFormat {
        NotSpecified,
        PEM,
        PKCS1
    };

    ~RSACipher() {
        if (_RsaObj)
            RSA_free(_RsaObj);
        _RsaObj = nullptr;
    }

    static RSACipher* Create() {
        RSACipher* aCipher = new RSACipher(RSA_new());
        if (aCipher->_RsaObj == nullptr) {
            delete aCipher;
            aCipher = nullptr;
        }
        return aCipher;
    }

    bool GenerateKey(int bits, unsigned int e = RSA_F4) {
        bool bSuccess = false;
        BIGNUM* bn_e = nullptr;

        bn_e = BN_new();
        if (bn_e == nullptr)
            goto ON_RSACipher_GenerateKey0_ERROR;

        if (!BN_set_word(bn_e, e))
            goto ON_RSACipher_GenerateKey0_ERROR;

        if (!RSA_generate_key_ex(_RsaObj, bits, bn_e, nullptr))
            goto ON_RSACipher_GenerateKey0_ERROR;

        bSuccess = true;

    ON_RSACipher_GenerateKey0_ERROR:
        if (bn_e)
            BN_free(bn_e);
        return bSuccess;
    }

    template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
    bool ExportKeyToFile(const std::string& filename) {
        static_assert(
            _Type == KeyType::PrivateKey || (_Format == KeyFormat::PEM || _Format == KeyFormat::PKCS1),
            "Not supported format."
        );

        bool bSuccess = false;
        BIO* bio_file = nullptr;

        bio_file = BIO_new_file(filename.c_str(), "w");
        if (bio_file == nullptr)
            goto ON_RSACipher_ExportKeyToFile_0_ERROR;

        if (_Type == KeyType::PrivateKey) {
            bSuccess = PEM_write_bio_RSAPrivateKey(bio_file, _RsaObj, nullptr, nullptr, 0, nullptr, nullptr) ? true : false;
        } else {
            if (_Format == KeyFormat::PEM)
                bSuccess = PEM_write_bio_RSA_PUBKEY(bio_file, _RsaObj) ? true : false;
            else if (_Format == KeyFormat::PKCS1)
                bSuccess = PEM_write_bio_RSAPublicKey(bio_file, _RsaObj) ? true : false;
        }

    ON_RSACipher_ExportKeyToFile_0_ERROR:
        return bSuccess;
    }

    template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
    std::string ExportKeyString() {
        static_assert(
            _Type == KeyType::PrivateKey || (_Format == KeyFormat::PEM || _Format == KeyFormat::PKCS1),
            "Not supported format."
        );

        std::string KeyString;
        BIO* bio_mem = nullptr;
        int len = 0;
        const char* lpdata = nullptr;

        bio_mem = BIO_new(BIO_s_mem());
        if (bio_mem == nullptr)
            goto ON_RSACipher_ExportKeyString_0_ERROR;

        if (_Type == KeyType::PrivateKey) {
            if (!PEM_write_bio_RSAPrivateKey(bio_mem, _RsaObj, nullptr, nullptr, 0, nullptr, nullptr))
                goto ON_RSACipher_ExportKeyString_0_ERROR;
        } else {
            if (_Format == KeyFormat::PEM) {
                if (!PEM_write_bio_RSA_PUBKEY(bio_mem, _RsaObj))
                    goto ON_RSACipher_ExportKeyString_0_ERROR;
            } else if (_Format == KeyFormat::PKCS1) {
                if (!PEM_write_bio_RSAPublicKey(bio_mem, _RsaObj))
                    goto ON_RSACipher_ExportKeyString_0_ERROR;
            }
        }

        len = BIO_get_mem_data(bio_mem, &lpdata);

        KeyString.resize(len);
        memcpy(KeyString.data(), lpdata, len);

    ON_RSACipher_ExportKeyString_0_ERROR:
        if (bio_mem)
            BIO_free_all(bio_mem);
        return KeyString;
    }

    template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
    bool ImportKeyFromFile(const std::string& filename) {
        static_assert(
            _Type == KeyType::PrivateKey || (_Format == KeyFormat::PEM || _Format == KeyFormat::PKCS1),
            "Not supported format."
        );

        bool bSuccess = false;
        BIO* bio_file = nullptr;
        RSA* _newRsaObj = nullptr;

        bio_file = BIO_new_file(filename.c_str(), "r");
        if (bio_file == nullptr)
            goto ON_RSACipher_ImportKeyFromFile_0_ERROR;

        if (_Type == KeyType::PrivateKey) {
            _newRsaObj = PEM_read_bio_RSAPrivateKey(bio_file, nullptr, nullptr, nullptr);
        } else {
            if (_Format == KeyFormat::PEM)
                _newRsaObj = PEM_read_bio_RSA_PUBKEY(bio_file, nullptr, nullptr, nullptr);
            else if (_Format == KeyFormat::PKCS1)
                _newRsaObj = PEM_read_bio_RSAPublicKey(bio_file, nullptr, nullptr, nullptr);
        }

        if (_newRsaObj) {
            RSA_free(_RsaObj);
            _RsaObj = _newRsaObj;
            bSuccess = true;
        }

    ON_RSACipher_ImportKeyFromFile_0_ERROR:
        if (bio_file)
            BIO_free_all(bio_file);
        return bSuccess;
    }

    template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
    bool ImportKeyString(const std::string& KeyString) {
        static_assert(
            _Type == KeyType::PrivateKey || (_Format == KeyFormat::PEM || _Format == KeyFormat::PKCS1),
            "Not supported format."
        );

        bool bSuccess = false;
        BIO* bio_mem = nullptr;
        RSA* _newRsaObj = nullptr;

        bio_mem = BIO_new(BIO_s_mem());
        if (bio_mem == nullptr)
            goto ON_RSACipher_ImportKeyString_0_ERROR;

        BIO_puts(bio_mem, KeyString.c_str());

        if (_Type == KeyType::PrivateKey) {
            _newRsaObj = PEM_read_bio_RSAPrivateKey(bio_mem, nullptr, nullptr, nullptr);
        } else {
            if (_Format == KeyFormat::PEM)
                _newRsaObj = PEM_read_bio_RSA_PUBKEY(bio_mem, nullptr, nullptr, nullptr);
            else if (_Format == KeyFormat::PKCS1)
                _newRsaObj = PEM_read_bio_RSAPublicKey(bio_mem, nullptr, nullptr, nullptr);
        }

        if (_newRsaObj) {
            RSA_free(_RsaObj);
            _RsaObj = _newRsaObj;
            bSuccess = true;
        }

    ON_RSACipher_ImportKeyString_0_ERROR:
        if (bio_mem)
            BIO_free_all(bio_mem);
        return bSuccess;
    }

    template<KeyType _Type = KeyType::PublicKey>
    int Encrypt(const void* from, int len, void* to, int padding) {
        int write_bytes = 0;

        if (_Type == KeyType::PrivateKey) {
            write_bytes = RSA_private_encrypt(len,
                                              reinterpret_cast<const unsigned char*>(from),
                                              reinterpret_cast<unsigned char*>(to),
                                              _RsaObj,
                                              padding);
        } else {
            write_bytes = RSA_public_encrypt(len,
                                             reinterpret_cast<const unsigned char*>(from),
                                             reinterpret_cast<unsigned char*>(to),
                                             _RsaObj,
                                             padding);
        }

        if (write_bytes == -1)
            write_bytes = 0;
        return write_bytes;
    }

    template<KeyType _Type = KeyType::PrivateKey>
    int Decrypt(const void* from, int len, void* to, int padding) {
        int write_bytes = 0;

        if (_Type == KeyType::PrivateKey) {
            write_bytes = RSA_private_decrypt(len,
                                              reinterpret_cast<const unsigned char*>(from),
                                              reinterpret_cast<unsigned char*>(to),
                                              _RsaObj,
                                              padding);
        } else {
            write_bytes = RSA_public_decrypt(len,
                                             reinterpret_cast<const unsigned char*>(from),
                                             reinterpret_cast<unsigned char*>(to),
                                             _RsaObj,
                                             padding);
        }

        if (write_bytes == -1)
            write_bytes = 0;
        return write_bytes;
    }

};
