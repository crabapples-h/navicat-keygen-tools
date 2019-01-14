#pragma once
#include "Exceptions.hpp"
#include "ResourceGuardOpenssl.hpp"
#include <openssl/pem.h>
#include <string>
#include <memory.h>

#ifdef _DEBUG
#pragma comment(lib, "libcryptoMTd.lib")
#else
#pragma comment(lib, "libcryptoMT.lib")
#endif
#pragma comment(lib, "WS2_32.lib")      // some symbol are used in OpenSSL static lib
#pragma comment(lib, "Crypt32.lib")     // some symbol are used in OpenSSL static lib

namespace Patcher {

    class RSACipher {
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
    private:
        ResourceGuard<OpensslRSATraits> _RsaObj;

        RSACipher() noexcept = default;
        RSACipher(RSA* pRsa) : _RsaObj(pRsa) {}

        // Copy constructor is not allowed
        RSACipher(const RSACipher&) = delete;

        // Copy assignment is not allowed
        RSACipher& operator=(const RSACipher&) = delete;

        template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
        static void _RSAToBIO(RSA* pRsaObject, BIO* pBioObject) {
            if constexpr (_Type == KeyType::PrivateKey) {
                if (!PEM_write_bio_RSAPrivateKey(bio_file, pRsaObject, nullptr, nullptr, 0, nullptr, nullptr))
                    throw Exception(__BASE_FILE__, __LINE__, 
                                    "PEM_write_bio_RSAPrivateKey fails.");
            } else {
                if constexpr (_Format == KeyFormat::PEM) {
                    if (!PEM_write_bio_RSA_PUBKEY(bio_file, pRsaObject))
                        throw Exception(__BASE_FILE__, __LINE__,
                                        "PEM_write_bio_RSA_PUBKEY fails.");
                } else if constexpr (_Format == KeyFormat::PKCS1) {
                    if (!PEM_write_bio_RSAPublicKey(bio_file, pRsaObject))
                        throw Exception(__BASE_FILE__, __LINE__,
                                        "PEM_write_bio_RSAPublicKey fails.");
                } else {
                    static_assert(_Format == KeyFormat::PEM || _Format == KeyFormat::PKCS1);
                }
            }
        }

        template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
        static RSA* _BIOToRSA(BIO* pBioObject) {
            RSA* pNewRsaObject;

            if constexpr (_Type == KeyType::PrivateKey) {
                pNewRsaObject = PEM_read_bio_RSAPrivateKey(bio_file, nullptr, nullptr, nullptr);
                if (pNewRsaObject == nullptr)
                    throw Exception(__BASE_FILE__, __LINE__, 
                                    "PEM_read_bio_RSAPrivateKey fails.");
            } else {
                if constexpr (_Format == KeyFormat::PEM) {
                    pNewRsaObject = PEM_read_bio_RSA_PUBKEY(bio_file, nullptr, nullptr, nullptr);
                    if (pNewRsaObject == nullptr)
                        throw Exception(__BASE_FILE__, __LINE__,
                                        "PEM_read_bio_RSA_PUBKEY fails.");
                } else if constexpr (_Format == KeyFormat::PKCS1) {
                    pNewRsaObject = PEM_read_bio_RSAPublicKey(bio_file, nullptr, nullptr, nullptr);
                    if (pNewRsaObject == nullptr)
                        throw Exception(__BASE_FILE__, __LINE__,
                                        "PEM_read_bio_RSAPublicKey fails.");
                } else {
                    static_assert(_Format == KeyFormat::PEM || _Format == KeyFormat::PKCS1);
                }
            }

            return pNewRsaObject;
        }

    public:

        static RSACipher* Create() {
            RSACipher* aCipher = new RSACipher(RSA_new());
            if (aCipher->_RsaObj == nullptr) {
                delete aCipher;
                aCipher = nullptr;
            }
            return aCipher;
        }

        void GenerateKey(int bits, unsigned int e = RSA_F4) {
            ResourceGuard<OpensslBNTraits> bn_e;

            bn_e.TakeHoldOf(BN_new());
            if (bn_e.IsValid() == false)
                throw OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(),
                                   "BN_new fails.");

            if (!BN_set_word(bn_e, e))
                throw Exception(__BASE_FILE__, __LINE__, 
                                "BN_set_word fails.");

            if (!RSA_generate_key_ex(_RsaObj, bits, bn_e, nullptr))
                throw OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(),
                                   "RSA_generate_key_ex fails.");
        }

        template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
        void ExportKeyToFile(const std::string& FileName) {
            ResourceGuard<OpensslBIOTraits> bio_file;

            bio_file.TakeHoldOf(BIO_new_file(FileName.c_str(), "w"));
            if (bio_file.IsValid() == false)
                throw Exception(__BASE_FILE__, __LINE__, 
                                "BIO_new_file fails.");

            _RSAToBIO<_Type, _Format>(_RsaObj, bio_file);
        }

        template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
        std::string ExportKeyString() {
            std::string result;
            ResourceGuard<OpensslBIOTraits> bio_mem;
            int DataSize;
            const char* pData = nullptr;

            bio_mem.TakeHoldOf(BIO_new(BIO_s_mem()));
            if (bio_mem.IsValid() == false)
                throw Exception(__BASE_FILE__, __LINE__,
                                "BIO_new fails.");

            _RSAToBIO<_Type, _Format>(_RsaObj, bio_mem);

            DataSize = BIO_get_mem_data(bio_mem, &pData);
            result.resize(DataSize);
            memcpy(result.data(), pData, DataSize);

            return result;
        }

        template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
        void ImportKeyFromFile(const std::string& FileName) {
            bool bSuccess = false;
            ResourceGuard<OpensslBIOTraits> bio_file;
            RSA* NewRsaObj;

            bio_file.TakeHoldOf(BIO_new_file(FileName.c_str(), "r"));
            if (bio_file.IsValid() == false)
                throw Exception(__BASE_FILE__, __LINE__,
                                "BIO_new_file fails.");

            NewRsaObj = _BIOToRSA<_Type, _Format>(bio_file);
            _RsaObj.Release();
            _RsaObj.TakeHoldOf(NewRsaObj);
        }

        template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
        void ImportKeyString(const std::string& KeyString) {
            ResourceGuard<OpensslBIOTraits> bio_mem;
            RSA* NewRsaObj;

            bio_mem = BIO_new(BIO_s_mem());
            if (bio_mem == nullptr)
                throw Exception(__BASE_FILE__, __LINE__,
                                "BIO_new fails.");

            if (BIO_puts(bio_mem, KeyString.c_str()) <= 0)
                throw Exception(__BASE_FILE__, __LINE__,
                                "BIO_puts fails.");

            NewRsaObj = _BIOToRSA<_Type, _Format>(bio_mem);
            _RsaObj.Release();
            _RsaObj.TakeHoldOf(NewRsaObj);
        }

        template<KeyType _Type = KeyType::PublicKey>
        int Encrypt(const void* from, int len, void* to, int padding) {
            int write_bytes;

            if constexpr (_Type == KeyType::PrivateKey) {
                write_bytes = RSA_private_encrypt(len,
                                                  reinterpret_cast<const unsigned char*>(from),
                                                  reinterpret_cast<unsigned char*>(to),
                                                  _RsaObj,
                                                  padding);
                if (write_bytes == -1)
                    throw OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(),
                                       "RSA_private_encrypt fails.");
            } else {
                write_bytes = RSA_public_encrypt(len,
                                                 reinterpret_cast<const unsigned char*>(from),
                                                 reinterpret_cast<unsigned char*>(to),
                                                 _RsaObj,
                                                 padding);
                if (write_bytes == -1)
                    throw OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(),
                                       "RSA_public_encrypt fails.");
            }

            return write_bytes;
        }

        template<KeyType _Type = KeyType::PrivateKey>
        int Decrypt(const void* from, int len, void* to, int padding) {
            int write_bytes;

            if constexpr (_Type == KeyType::PrivateKey) {
                write_bytes = RSA_private_decrypt(len,
                                                  reinterpret_cast<const unsigned char*>(from),
                                                  reinterpret_cast<unsigned char*>(to),
                                                  _RsaObj,
                                                  padding);
                if (write_bytes == -1)
                    throw OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(),
                                       "RSA_private_decrypt fails.");
            } else {
                write_bytes = RSA_public_decrypt(len,
                                                 reinterpret_cast<const unsigned char*>(from),
                                                 reinterpret_cast<unsigned char*>(to),
                                                 _RsaObj,
                                                 padding);
                if (write_bytes == -1)
                    throw OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(),
                                       "RSA_public_decrypt fails.");
            }

            return write_bytes;
        }

    };

}

