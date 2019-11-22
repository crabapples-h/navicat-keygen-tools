#pragma once
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>

#include <string>

#include "ExceptionOpenssl.hpp"
#include "ResourceOwned.hpp"
#include "ResourceTraitsOpenssl.hpp"

enum class RSAKeyType {
    PrivateKey,
    PublicKey
};

enum class RSAKeyFormat {
    PEM,
    PKCS1
};

class RSACipher {
private:
    ResourceOwned<OpensslRSATraits> pvt_RsaObj;

    template<RSAKeyType __Type, RSAKeyFormat __Format>
    static void pvt_WriteRSAToBIO(RSA* lpRSA, BIO* lpBIO) {
        if constexpr (__Type == RSAKeyType::PrivateKey) {
            if (PEM_write_bio_RSAPrivateKey(lpBIO, lpRSA, nullptr, nullptr, 0, nullptr, nullptr) == 0) {
                // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                throw nkg::Exception(__FILE__, __LINE__, "PEM_write_bio_RSAPrivateKey failed.");
            }
        } else {
            if constexpr (__Format == RSAKeyFormat::PEM) {
                if (PEM_write_bio_RSA_PUBKEY(lpBIO, lpRSA) == 0) {
                    // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                    throw nkg::Exception(__FILE__, __LINE__, "PEM_write_bio_RSA_PUBKEY failed.");
                }
            } else if constexpr (__Format == RSAKeyFormat::PKCS1) {
                if (PEM_write_bio_RSAPublicKey(lpBIO, lpRSA) == 0) {
                    // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                    throw nkg::Exception(__FILE__, __LINE__, "PEM_write_bio_RSAPublicKey failed.");
                }
            } else {
                static_assert(__Format == RSAKeyFormat::PEM || __Format == RSAKeyFormat::PKCS1);
                __builtin_unreachable();
            }
        }
    }

    template<RSAKeyType _Type, RSAKeyFormat _Format>
    [[nodiscard]]
    static RSA* pvt_ReadRSAFromBIO(BIO* lpBIO) {
        RSA* lpRSA;

        if constexpr (_Type == RSAKeyType::PrivateKey) {
            lpRSA = PEM_read_bio_RSAPrivateKey(lpBIO, nullptr, nullptr, nullptr);
            if (lpRSA == nullptr) {
                // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                throw nkg::Exception(__FILE__, __LINE__, "PEM_read_bio_RSAPrivateKey failed.");
            }
        } else {
            if constexpr (_Format == RSAKeyFormat::PEM) {
                lpRSA = PEM_read_bio_RSA_PUBKEY(lpBIO, nullptr, nullptr, nullptr);
                if (lpRSA == nullptr) {
                    // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                    throw nkg::Exception(__FILE__, __LINE__, " -> PEM_read_bio_RSA_PUBKEY failed.");
                }
            } else if constexpr (_Format == RSAKeyFormat::PKCS1) {
                lpRSA = PEM_read_bio_RSAPublicKey(lpBIO, nullptr, nullptr, nullptr);
                if (lpRSA == nullptr) {
                    // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
                    throw nkg::Exception(__FILE__, __LINE__, "PEM_read_bio_RSAPublicKey failed.");
                }
            } else {
                static_assert(_Format == RSAKeyFormat::PEM || _Format == RSAKeyFormat::PKCS1);
                __builtin_unreachable();
            }
        }

        return lpRSA;
    }

public:

    RSACipher() : pvt_RsaObj(OpensslRSATraits{}, RSA_new()) {
        if (pvt_RsaObj.IsValid() == false) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::OpensslError(__FILE__, __LINE__, ERR_get_error(), "RSA_new failed.");
        }
    }

    [[nodiscard]]
    size_t Bits() const {
#if (OPENSSL_VERSION_NUMBER & 0xffff0000) == 0x10000000     // openssl 1.0.x
        if (pvt_RsaObj->n == nullptr) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::Exception(__FILE__, __LINE__, "RSA modulus has not been set.");
        } else {
            return BN_num_bits(pvt_RsaObj->n);
        }
#elif (OPENSSL_VERSION_NUMBER & 0xffff0000) == 0x10100000     // openssl 1.1.x
        return RSA_bits(pvt_RsaObj);
#else
#error "Unexpected openssl version!"
#endif
    }

    void GenerateKey(int bits, unsigned int e = RSA_F4) {
        ResourceOwned bn_e(OpensslBNTraits{}, BN_new());

        if (bn_e.IsValid() == false) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::OpensslError(__FILE__, __LINE__, ERR_get_error(), "BN_new failed.");
        }

        if (!BN_set_word(bn_e, e)) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::Exception(__FILE__, __LINE__, "BN_set_word failed.");
        }

        if (!RSA_generate_key_ex(pvt_RsaObj, bits, bn_e, nullptr)) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::OpensslError(__FILE__, __LINE__, ERR_get_error(), "RSA_generate_key_ex failed.");
        }
    }

    template<RSAKeyType __Type, RSAKeyFormat __Format>
    void ExportKeyToFile(const std::string& FileName) const {
        ResourceOwned BioFile(OpensslBIOTraits{}, BIO_new_file(FileName.c_str(), "w"));

        if (BioFile.IsValid() == false) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::Exception(__FILE__, __LINE__, "BIO_new_file failed.");
        }

        pvt_WriteRSAToBIO<__Type, __Format>(pvt_RsaObj, BioFile);
    }

    template<RSAKeyType __Type, RSAKeyFormat __Format>
    [[nodiscard]]
    std::string ExportKeyString() const {
        ResourceOwned BioMemory(OpensslBIOTraits{}, BIO_new(BIO_s_mem()));
        long StringLength;
        const char* StringChars = nullptr;

        if (BioMemory.IsValid() == false) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::Exception(__FILE__, __LINE__, "BIO_new failed.");
        }

        pvt_WriteRSAToBIO<__Type, __Format>(pvt_RsaObj, BioMemory);

        StringLength = BIO_get_mem_data(BioMemory, &StringChars);

        return std::string(StringChars, StringLength);
    }

    template<RSAKeyType __Type, RSAKeyFormat __Format>
    void ImportKeyFromFile(const std::string& FileName) {
        ResourceOwned BioFile(OpensslBIOTraits{}, BIO_new_file(FileName.c_str(), "r"));

        if (BioFile.IsValid() == false) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::Exception(__FILE__, __LINE__, "BIO_new_file failed.");
        }

        pvt_RsaObj.TakeOver(pvt_ReadRSAFromBIO<__Type, __Format>(BioFile));
    }

    template<RSAKeyType __Type, RSAKeyFormat __Format>
    void ImportKeyString(const std::string& KeyString) {
        ResourceOwned BioMemory(OpensslBIOTraits{}, BIO_new(BIO_s_mem()));
        RSA* NewRsaObj;

        if (BioMemory.IsValid() == false) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::Exception(__FILE__, __LINE__, "BIO_new failed.");
        }

        if (BIO_puts(BioMemory, KeyString.c_str()) <= 0) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::Exception(__FILE__, __LINE__, "BIO_puts failed.");
        }

        pvt_RsaObj.TakeOver(pvt_ReadRSAFromBIO<__Type, __Format>(BioMemory));
    }

    template<RSAKeyType __Type = RSAKeyType::PublicKey>
    size_t Encrypt(const void* lpFrom, size_t cbFrom, void* lpTo, int Padding) const {
        int BytesWritten;

        if (cbFrom > INT_MAX) {
            // NOLINTNEXTLINE: allow exceptions that is not derived lpFrom std::exception
            throw nkg::Exception(__FILE__, __LINE__, "Length overflowed.");
        }

        if constexpr (__Type == RSAKeyType::PrivateKey) {
            BytesWritten = RSA_private_encrypt(
                static_cast<int>(cbFrom),
                reinterpret_cast<const unsigned char*>(lpFrom),
                reinterpret_cast<unsigned char*>(lpTo),
                pvt_RsaObj,
                Padding
            );

            if (BytesWritten == -1) {
                // NOLINTNEXTLINE: allow exceptions that is not derived lpFrom std::exception
                throw nkg::OpensslError(__FILE__, __LINE__, ERR_get_error(), "RSA_private_encrypt failed.");
            }
        } else {
            BytesWritten = RSA_public_encrypt(
                static_cast<int>(cbFrom),
                reinterpret_cast<const unsigned char*>(lpFrom),
                reinterpret_cast<unsigned char*>(lpTo),
                pvt_RsaObj,
                Padding
            );

            if (BytesWritten == -1) {
                // NOLINTNEXTLINE: allow exceptions that is not derived lpFrom std::exception
                throw nkg::OpensslError(__FILE__, __LINE__, ERR_get_error(), "RSA_public_encrypt failed.");
            }
        }

        return BytesWritten;
    }

    template<RSAKeyType __Type = RSAKeyType::PrivateKey>
    size_t Decrypt(const void* lpFrom, int cbFrom, void* lpTo, int Padding) const {
        int BytesWritten;

        if (cbFrom > INT_MAX) {
            // NOLINTNEXTLINE: allow exceptions that is not derived lpFrom std::exception
            throw nkg::Exception(__FILE__, __LINE__, "Length overflowed.");
        }

        if constexpr (__Type == RSAKeyType::PrivateKey) {
            BytesWritten = RSA_private_decrypt(
                cbFrom,
                reinterpret_cast<const unsigned char*>(lpFrom),
                reinterpret_cast<unsigned char*>(lpTo),
                pvt_RsaObj,
                Padding
            );

            if (BytesWritten == -1) {
                // NOLINTNEXTLINE: allow exceptions that is not derived lpFrom std::exception
                throw nkg::OpensslError(__FILE__, __LINE__, ERR_get_error(), "RSA_private_decrypt failed.");
            }
        } else {
            BytesWritten = RSA_public_decrypt(
                cbFrom,
                reinterpret_cast<const unsigned char*>(lpFrom),
                reinterpret_cast<unsigned char*>(lpTo),
                pvt_RsaObj,
                Padding
            );

            if (BytesWritten == -1) {
                // NOLINTNEXTLINE: allow exceptions that is not derived lpFrom std::exception
                throw nkg::OpensslError(__FILE__, __LINE__, ERR_get_error(), "RSA_public_decrypt failed.");
            }
        }

        return BytesWritten;
    }
};