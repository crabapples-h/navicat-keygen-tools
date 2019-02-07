#pragma once
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <string>
#include <memory.h>
#include "ResourceObject.hpp"
#include "Exception.hpp"

struct OpensslBIOTraits {
    using HandleType = BIO*;
    static inline const HandleType InvalidValue = nullptr;
    static constexpr auto& Releasor = BIO_free;
};

struct OpensslBIOChainTraits {
    using HandleType = BIO*;
    static inline const HandleType InvalidValue = nullptr;
    static constexpr auto& Releasor = BIO_free_all;
};

struct OpensslBNTraits {
    using HandleType = BIGNUM*;
    static inline const HandleType InvalidValue = nullptr;
    static constexpr auto& Releasor = BN_free;
};

struct OpensslRSATraits {
    using HandleType = RSA*;
    static inline const HandleType InvalidValue = nullptr;
    static constexpr auto& Releasor = RSA_free;
};

class OpensslError : public Exception {
private:
    const unsigned long _$$_ErrorCode;
public:

    OpensslError(const char* FileName,
                 size_t Line,
                 unsigned long Code,
                 const char* Message) noexcept :
        Exception(FileName, Line, Message),
        _$$_ErrorCode(Code) {}

    virtual bool HasErrorCode() const noexcept override {
        return true;
    }

    virtual unsigned long ErrorCode() const noexcept override {
        return _$$_ErrorCode;
    }

    virtual const char* ErrorString() const noexcept override {
        return ERR_error_string(_$$_ErrorCode, nullptr);
    }

};

enum class RSAKeyType {
    PrivateKey,
    PublicKey
};

enum class RSAKeyFormat {
    NotSpecified,
    PEM,
    PKCS1
};

class RSACipher {
private:
    ResourceObject<OpensslRSATraits> _$$_RsaObj;

    RSACipher(RSA* pRsa) : _$$_RsaObj(pRsa) {}

    // Copy constructor is not allowed
    RSACipher(const RSACipher&) = delete;

    // Copy assignment is not allowed
    RSACipher& operator=(const RSACipher&) = delete;

    template<RSAKeyType __Type, RSAKeyFormat __Format = RSAKeyFormat::NotSpecified>
    static void _RSAToBIO(RSA* pRsaObject, BIO* pBioObject) {
        if constexpr (__Type == RSAKeyType::PrivateKey) {
            if (!PEM_write_bio_RSAPrivateKey(pBioObject, pRsaObject, nullptr, nullptr, 0, nullptr, nullptr))
                throw Exception(__FILE__, __LINE__,
                                "PEM_write_bio_RSAPrivateKey fails.");
        } else {
            if constexpr (__Format == RSAKeyFormat::PEM) {
                if (!PEM_write_bio_RSA_PUBKEY(pBioObject, pRsaObject))
                    throw Exception(__FILE__, __LINE__,
                                    "PEM_write_bio_RSA_PUBKEY fails.");
            } else if constexpr (__Format == RSAKeyFormat::PKCS1) {
                if (!PEM_write_bio_RSAPublicKey(pBioObject, pRsaObject))
                    throw Exception(__FILE__, __LINE__,
                                    "PEM_write_bio_RSAPublicKey fails.");
            } else {
                static_assert(__Format == RSAKeyFormat::PEM || __Format == RSAKeyFormat::PKCS1);
            }
        }
    }

    template<RSAKeyType _Type, RSAKeyFormat _Format = RSAKeyFormat::NotSpecified>
    static RSA* _BIOToRSA(BIO* pBioObject) {
        RSA* pNewRsaObject;

        if constexpr (_Type == RSAKeyType::PrivateKey) {
            pNewRsaObject = PEM_read_bio_RSAPrivateKey(pBioObject, nullptr, nullptr, nullptr);
            if (pNewRsaObject == nullptr)
                throw Exception(__FILE__, __LINE__,
                                "PEM_read_bio_RSAPrivateKey fails.");
        } else {
            if constexpr (_Format == RSAKeyFormat::PEM) {
                pNewRsaObject = PEM_read_bio_RSA_PUBKEY(pBioObject, nullptr, nullptr, nullptr);
                if (pNewRsaObject == nullptr)
                    throw Exception(__FILE__, __LINE__,
                                    "PEM_read_bio_RSA_PUBKEY fails.");
            } else if constexpr (_Format == RSAKeyFormat::PKCS1) {
                pNewRsaObject = PEM_read_bio_RSAPublicKey(pBioObject, nullptr, nullptr, nullptr);
                if (pNewRsaObject == nullptr)
                    throw Exception(__FILE__, __LINE__,
                                    "PEM_read_bio_RSAPublicKey fails.");
            } else {
                static_assert(_Format == RSAKeyFormat::PEM || _Format == RSAKeyFormat::PKCS1);
            }
        }

        return pNewRsaObject;
    }

public:

    static RSACipher* Create() {
        RSACipher* aCipher = new RSACipher(RSA_new());
        if (aCipher->_$$_RsaObj.IsValid() == false) {
            delete aCipher;
            aCipher = nullptr;
        }
        return aCipher;
    }

    RSACipher() : _$$_RsaObj(RSA_new()) {
        if (_$$_RsaObj.IsValid() == false)
            throw OpensslError(__FILE__, __LINE__, ERR_get_error(),
                               "RSA_new fails.");
    }

    void GenerateKey(int bits, unsigned int e = RSA_F4) {
        ResourceObject<OpensslBNTraits> bn_e;

        bn_e.TakeOver(BN_new());
        if (bn_e.IsValid() == false)
            throw OpensslError(__FILE__, __LINE__, ERR_get_error(),
                               "BN_new fails.");

        if (!BN_set_word(bn_e, e))
            throw Exception(__FILE__, __LINE__,
                            "BN_set_word fails.");

        if (!RSA_generate_key_ex(_$$_RsaObj, bits, bn_e, nullptr))
            throw OpensslError(__FILE__, __LINE__, ERR_get_error(),
                               "RSA_generate_key_ex fails.");
    }

    template<RSAKeyType _Type, RSAKeyFormat _Format = RSAKeyFormat::NotSpecified>
    void ExportKeyToFile(const std::string& FileName) {
        ResourceObject<OpensslBIOTraits> bio_file;

        bio_file.TakeOver(BIO_new_file(FileName.c_str(), "w"));
        if (bio_file.IsValid() == false)
            throw Exception(__FILE__, __LINE__,
                            "BIO_new_file fails.");

        _RSAToBIO<_Type, _Format>(_$$_RsaObj, bio_file);
    }

    template<RSAKeyType _Type, RSAKeyFormat _Format = RSAKeyFormat::NotSpecified>
    std::string ExportKeyString() {
        std::string result;
        ResourceObject<OpensslBIOTraits> bio_mem;
        long DataSize;
        const char* pData = nullptr;

        bio_mem.TakeOver(BIO_new(BIO_s_mem()));
        if (bio_mem.IsValid() == false)
            throw Exception(__FILE__, __LINE__,
                            "BIO_new fails.");

        _RSAToBIO<_Type, _Format>(_$$_RsaObj, bio_mem);

        DataSize = BIO_get_mem_data(bio_mem, &pData);
        result.resize(DataSize);
        memcpy(result.data(), pData, DataSize);

        return result;
    }

    template<RSAKeyType _Type, RSAKeyFormat _Format = RSAKeyFormat::NotSpecified>
    void ImportKeyFromFile(const std::string& FileName) {
        bool bSuccess = false;
        ResourceObject<OpensslBIOTraits> bio_file;
        RSA* NewRsaObj;

        bio_file.TakeOver(BIO_new_file(FileName.c_str(), "r"));
        if (bio_file.IsValid() == false)
            throw Exception(__FILE__, __LINE__,
                            "BIO_new_file fails.");

        NewRsaObj = _BIOToRSA<_Type, _Format>(bio_file);
        _$$_RsaObj.Release();
        _$$_RsaObj.TakeOver(NewRsaObj);
    }

    template<RSAKeyType _Type, RSAKeyFormat _Format = RSAKeyFormat::NotSpecified>
    void ImportKeyString(const std::string& KeyString) {
        ResourceObject<OpensslBIOTraits> bio_mem;
        RSA* NewRsaObj;

        bio_mem = BIO_new(BIO_s_mem());
        if (bio_mem == nullptr)
            throw Exception(__FILE__, __LINE__,
                            "BIO_new fails.");

        if (BIO_puts(bio_mem, KeyString.c_str()) <= 0)
            throw Exception(__FILE__, __LINE__,
                            "BIO_puts fails.");

        NewRsaObj = _BIOToRSA<_Type, _Format>(bio_mem);
        _$$_RsaObj.Release();
        _$$_RsaObj.TakeOver(NewRsaObj);
    }

    template<RSAKeyType _Type = RSAKeyType::PublicKey>
    int Encrypt(const void* from, int len, void* to, int padding) {
        int write_bytes;

        if constexpr (_Type == RSAKeyType::PrivateKey) {
            write_bytes = RSA_private_encrypt(len,
                                              reinterpret_cast<const unsigned char*>(from),
                                              reinterpret_cast<unsigned char*>(to),
                                              _$$_RsaObj,
                                              padding);
            if (write_bytes == -1)
                throw OpensslError(__FILE__, __LINE__, ERR_get_error(),
                                   "RSA_private_encrypt fails.");
        } else {
            write_bytes = RSA_public_encrypt(len,
                                             reinterpret_cast<const unsigned char*>(from),
                                             reinterpret_cast<unsigned char*>(to),
                                             _$$_RsaObj,
                                             padding);
            if (write_bytes == -1)
                throw OpensslError(__FILE__, __LINE__, ERR_get_error(),
                                   "RSA_public_encrypt fails.");
        }

        return write_bytes;
    }

    template<RSAKeyType _Type = RSAKeyType::PrivateKey>
    int Decrypt(const void* from, int len, void* to, int padding) {
        int write_bytes;

        if constexpr (_Type == RSAKeyType::PrivateKey) {
            write_bytes = RSA_private_decrypt(len,
                                              reinterpret_cast<const unsigned char*>(from),
                                              reinterpret_cast<unsigned char*>(to),
                                              _$$_RsaObj,
                                              padding);
            if (write_bytes == -1)
                throw OpensslError(__FILE__, __LINE__, ERR_get_error(),
                                   "RSA_private_decrypt fails.");
        } else {
            write_bytes = RSA_public_decrypt(len,
                                             reinterpret_cast<const unsigned char*>(from),
                                             reinterpret_cast<unsigned char*>(to),
                                             _$$_RsaObj,
                                             padding);
            if (write_bytes == -1)
                throw OpensslError(__FILE__, __LINE__, ERR_get_error(),
                                   "RSA_public_decrypt fails.");
        }

        return write_bytes;
    }

};

