#pragma once
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include "Exception.hpp"
#include "ExceptionOpenssl.hpp"
#include "ResourceOwned.hpp"
#include "ResourceTraitsOpenssl.hpp"

#undef NKG_CURRENT_SOURCE_FILE
#undef NKG_CURRENT_SOURCE_LINE
#define NKG_CURRENT_SOURCE_FILE() TEXT(".\\common\\RSACipher.hpp")
#define NKG_CURRENT_SOURCE_LINE() __LINE__

namespace nkg {

    enum class RSAKeyType {
        PrivateKey,
        PublicKey
    };

    enum class RSAKeyFormat {
        PEM,
        PKCS1
    };

    class RSACipher final : private ResourceOwned<OpensslRSATraits> {
    private:

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        static void _WriteRSAToBIO(RSA* lpRSA, BIO* lpBIO) {
            if constexpr (__Type == RSAKeyType::PrivateKey) {
                if (PEM_write_bio_RSAPrivateKey(lpBIO, lpRSA, nullptr, nullptr, 0, nullptr, nullptr) == 0) {
                    throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PEM_write_bio_RSAPrivateKey failed."));
                }
            }

            if constexpr (__Type == RSAKeyType::PublicKey) {
                if constexpr (__Format == RSAKeyFormat::PEM) {
                    if (PEM_write_bio_RSA_PUBKEY(lpBIO, lpRSA) == 0) {
                        throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PEM_write_bio_RSA_PUBKEY failed."));
                    }
                }

                if constexpr (__Format == RSAKeyFormat::PKCS1) {
                    if (PEM_write_bio_RSAPublicKey(lpBIO, lpRSA) == 0) {
                        throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PEM_write_bio_RSAPublicKey failed."));
                    }
                }

                static_assert(__Format == RSAKeyFormat::PEM || __Format == RSAKeyFormat::PKCS1);
            }

            static_assert(__Type == RSAKeyType::PrivateKey || __Type == RSAKeyType::PublicKey);
        }

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        [[nodiscard]]
        static RSA* _ReadRSAFromBIO(BIO* lpBIO) {
            RSA* lpRSA;

            if constexpr (__Type == RSAKeyType::PrivateKey) {
                lpRSA = PEM_read_bio_RSAPrivateKey(lpBIO, nullptr, nullptr, nullptr);
                if (lpRSA == nullptr) {
                    throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PEM_read_bio_RSAPrivateKey failed."))
                        .AddHint(TEXT("Are you sure that you DO provide a valid RSA private key file?"));
                }
            }

            if constexpr (__Type == RSAKeyType::PublicKey) {
                if constexpr (__Format == RSAKeyFormat::PEM) {
                    lpRSA = PEM_read_bio_RSA_PUBKEY(lpBIO, nullptr, nullptr, nullptr);
                    if (lpRSA == nullptr) {
                        throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PEM_read_bio_RSA_PUBKEY failed."))
                            .AddHint(TEXT("Are you sure that you DO provide a valid RSA public key file with PEM format?"));
                    }
                }

                if constexpr (__Format == RSAKeyFormat::PKCS1) {
                    lpRSA = PEM_read_bio_RSAPublicKey(lpBIO, nullptr, nullptr, nullptr);
                    if (lpRSA == nullptr) {
                        throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("PEM_read_bio_RSAPublicKey failed."))
                            .AddHint(TEXT("Are you sure that you DO provide a valid RSA public key file with PKCS1 format?"));
                    }
                }

                static_assert(__Format == RSAKeyFormat::PEM || __Format == RSAKeyFormat::PKCS1);
            }

            static_assert(__Type == RSAKeyType::PrivateKey || __Type == RSAKeyType::PublicKey);

            return lpRSA;
        }

    public:

        RSACipher() : ResourceOwned<OpensslRSATraits>(RSA_new()) {
            if (IsValid() == false) {
                throw OpensslError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), ERR_get_error(), TEXT("RSA_new failed."));
            }
        }

        [[nodiscard]]
        size_t Bits() const {
            if (Get()->n == nullptr) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("RSA modulus has not been set."));
            } else {
                return BN_num_bits(Get()->n);
            }
        }

        void GenerateKey(int bits, unsigned int e = RSA_F4) {
            ResourceOwned<OpensslBNTraits> bn_e(BN_new());

            if (bn_e.IsValid() == false) {
                throw OpensslError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), ERR_get_error(), TEXT("BN_new failed."));
            }

            if (!BN_set_word(bn_e, e)) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("BN_set_word failed."));
            }

            if (!RSA_generate_key_ex(Get(), bits, bn_e, nullptr)) {
                throw OpensslError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), ERR_get_error(), TEXT("RSA_generate_key_ex failed."));
            }
        }

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        void ExportKeyToFile(const std::xstring& FileName) const {
            ResourceOwned<OpensslBIOTraits> BioFile(BIO_new_file(FileName.explicit_string(CP_UTF8).c_str(), "w"));

            if (BioFile.IsValid() == false) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("BIO_new_file failed."));
            }

            _WriteRSAToBIO<__Type, __Format>(Get(), BioFile);
        }

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        [[nodiscard]]
        std::string ExportKeyString() const {
            ResourceOwned<OpensslBIOTraits> BioMemory(BIO_new(BIO_s_mem()));
            long StringLength;
            const char* StringChars = nullptr;

            if (BioMemory.IsValid() == false) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("BIO_new failed."));
            }

            _WriteRSAToBIO<__Type, __Format>(Get(), BioMemory);

            StringLength = BIO_get_mem_data(BioMemory.Get(), &StringChars);

            return std::string(StringChars, StringLength);
        }

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        void ImportKeyFromFile(const std::xstring& FileName) {
            ResourceOwned<OpensslBIOTraits> BioFile(BIO_new_file(FileName.explicit_string(CP_UTF8).c_str(), "r"));

            if (BioFile.IsValid() == false) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("BIO_new_file failed."));
            }

            TakeOver(_ReadRSAFromBIO<__Type, __Format>(BioFile));
        }

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        void ImportKeyString(const std::string& KeyString) {
            ResourceOwned<OpensslBIOTraits> BioMemory(BIO_new(BIO_s_mem()));

            if (BioMemory.IsValid() == false) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("BIO_new failed."));
            }

            if (BIO_puts(BioMemory.Get(), KeyString.c_str()) <= 0) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("BIO_puts failed."));
            }

            TakeOver(_ReadRSAFromBIO<__Type, __Format>(BioMemory));
        }

        template<RSAKeyType __Type = RSAKeyType::PublicKey>
        size_t Encrypt(const void* lpFrom, size_t cbFrom, void* lpTo, int Padding) const {
            int BytesWritten;

            if (cbFrom > INT_MAX) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Length overflowed."));
            }

            if constexpr (__Type == RSAKeyType::PrivateKey) {
                BytesWritten = RSA_private_encrypt(
                    static_cast<int>(cbFrom),
                    reinterpret_cast<const unsigned char*>(lpFrom),
                    reinterpret_cast<unsigned char*>(lpTo),
                    Get(),
                    Padding
                );

                if (BytesWritten == -1) {
                    throw OpensslError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), ERR_get_error(), TEXT("RSA_private_encrypt failed."));
                }
            } else {
                BytesWritten = RSA_public_encrypt(
                    static_cast<int>(cbFrom),
                    reinterpret_cast<const unsigned char*>(lpFrom),
                    reinterpret_cast<unsigned char*>(lpTo),
                    Get(),
                    Padding
                );

                if (BytesWritten == -1) {
                    throw OpensslError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), ERR_get_error(), TEXT("RSA_public_encrypt failed."));
                }
            }

            return BytesWritten;
        }

        template<RSAKeyType __Type = RSAKeyType::PrivateKey>
        size_t Decrypt(const void* lpFrom, size_t cbFrom, void* lpTo, int Padding) const {
            int BytesWritten;

            if (cbFrom > INT_MAX) {
                throw Exception(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), TEXT("Length overflowed."));
            }

            if constexpr (__Type == RSAKeyType::PrivateKey) {
                BytesWritten = RSA_private_decrypt(
                    static_cast<int>(cbFrom),
                    reinterpret_cast<const unsigned char*>(lpFrom),
                    reinterpret_cast<unsigned char*>(lpTo),
                    Get(),
                    Padding
                );

                if (BytesWritten == -1) {
                    throw OpensslError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), ERR_get_error(), TEXT("RSA_private_decrypt failed."))
                        .AddHint(TEXT("Are your sure you DO provide a correct private key?"));
                }
            } else {
                BytesWritten = RSA_public_decrypt(
                    static_cast<int>(cbFrom),
                    reinterpret_cast<const unsigned char*>(lpFrom),
                    reinterpret_cast<unsigned char*>(lpTo),
                    Get(),
                    Padding
                );

                if (BytesWritten == -1) {
                    throw OpensslError(NKG_CURRENT_SOURCE_FILE(), NKG_CURRENT_SOURCE_LINE(), ERR_get_error(), TEXT("RSA_public_decrypt failed."))
                        .AddHint(TEXT("Are your sure you DO provide a correct public key?"));
                }
            }

            return BytesWritten;
        }
    };

}
