#pragma once
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <string>
#include "Exception.hpp"
#include "ExceptionOpenssl.hpp"
#include "ResourceWrapper.hpp"
#include "ResourceTraitsOpenssl.hpp"

namespace nkg {

    enum class RSAKeyType {
        PrivateKey,
        PublicKey
    };

    enum class RSAKeyFormat {
        PEM,
        PKCS1
    };

    class RSACipher final : private ARL::ResourceWrapper<ARL::ResourceTraits::OpensslRSA> {
    private:

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        static void _WriteRSAToBIO(RSA* lpRSA, BIO* lpBIO) {
            if constexpr (__Type == RSAKeyType::PrivateKey) {
                if (PEM_write_bio_RSAPrivateKey(lpBIO, lpRSA, nullptr, nullptr, 0, nullptr, nullptr) == 0) {
                    throw ARL::Exception(__BASE_FILE__, __LINE__, "PEM_write_bio_RSAPrivateKey failed.");
                }
            }

            if constexpr (__Type == RSAKeyType::PublicKey) {
                if constexpr (__Format == RSAKeyFormat::PEM) {
                    if (PEM_write_bio_RSA_PUBKEY(lpBIO, lpRSA) == 0) {
                        throw ARL::Exception(__BASE_FILE__, __LINE__, "PEM_write_bio_RSA_PUBKEY failed.");
                    }
                }

                if constexpr (__Format == RSAKeyFormat::PKCS1) {
                    if (PEM_write_bio_RSAPublicKey(lpBIO, lpRSA) == 0) {
                        throw ARL::Exception(__BASE_FILE__, __LINE__, "PEM_write_bio_RSAPublicKey failed.");
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
                    throw ARL::Exception(__BASE_FILE__, __LINE__, "PEM_read_bio_RSAPrivateKey failed.")
                        .PushHint("Are you sure that you DO provide a valid RSA private key file?");
                }
            }

            if constexpr (__Type == RSAKeyType::PublicKey) {
                if constexpr (__Format == RSAKeyFormat::PEM) {
                    lpRSA = PEM_read_bio_RSA_PUBKEY(lpBIO, nullptr, nullptr, nullptr);
                    if (lpRSA == nullptr) {
                        throw ARL::Exception(__BASE_FILE__, __LINE__, "PEM_read_bio_RSA_PUBKEY failed.")
                            .PushHint("Are you sure that you DO provide a valid RSA public key file with PEM format?");
                    }
                }

                if constexpr (__Format == RSAKeyFormat::PKCS1) {
                    lpRSA = PEM_read_bio_RSAPublicKey(lpBIO, nullptr, nullptr, nullptr);
                    if (lpRSA == nullptr) {
                        throw ARL::Exception(__BASE_FILE__, __LINE__, "PEM_read_bio_RSAPublicKey failed.")
                            .PushHint("Are you sure that you DO provide a valid RSA public key file with PKCS1 format?");
                    }
                }

                static_assert(__Format == RSAKeyFormat::PEM || __Format == RSAKeyFormat::PKCS1);
            }

            static_assert(__Type == RSAKeyType::PrivateKey || __Type == RSAKeyType::PublicKey);

            return lpRSA;
        }

    public:

        RSACipher() : ARL::ResourceWrapper<ARL::ResourceTraits::OpensslRSA>(RSA_new()) {
            if (IsValid() == false) {
                throw ARL::OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(), "RSA_new failed.");
            }
        }

        [[nodiscard]]
        size_t Bits() const {
#if (OPENSSL_VERSION_NUMBER & 0xffff0000) == 0x10000000     // openssl 1.0.x
            if (Get()->n == nullptr) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "RSA modulus has not been set.");
            } else {
                return BN_num_bits(Get()->n);
            }
#elif (OPENSSL_VERSION_NUMBER & 0xffff0000) == 0x10100000     // openssl 1.1.x
            return RSA_bits(Get());
#else
            return RSA_bits(Get());
#endif
        }

        void GenerateKey(int bits, unsigned int e = RSA_F4) {
            ARL::ResourceWrapper bn_e{ ARL::ResourceTraits::OpensslBIGNUM{} };

            bn_e.TakeOver(BN_new());
            if (bn_e.IsValid() == false) {
                throw ARL::OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(), "BN_new failed.");
            }

            if (!BN_set_word(bn_e, e)) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "BN_set_word failed.");
            }

            if (!RSA_generate_key_ex(Get(), bits, bn_e, nullptr)) {
                throw ARL::OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(), "RSA_generate_key_ex failed.");
            }
        }

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        void ExportKeyToFile(std::string_view FileName) const {
            ARL::ResourceWrapper KeyFile{ ARL::ResourceTraits::OpensslBIO{} };

            KeyFile.TakeOver(BIO_new_file(FileName.data(), "w"));
            if (KeyFile.IsValid() == false) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "BIO_new_file failed.");
            }

            _WriteRSAToBIO<__Type, __Format>(Get(), KeyFile);
        }

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        [[nodiscard]]
        std::string ExportKeyString() const {
            ARL::ResourceWrapper TempMemory{ ARL::ResourceTraits::OpensslBIO{} };
            const char* lpsz = nullptr;

            TempMemory.TakeOver(BIO_new(BIO_s_mem()));
            if (TempMemory.IsValid() == false) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "BIO_new failed.");
            }

            _WriteRSAToBIO<__Type, __Format>(Get(), TempMemory);

            auto l = BIO_get_mem_data(TempMemory.Get(), &lpsz);

            std::string KeyString(lpsz, l);
            while (KeyString.back() == '\n' || KeyString.back() == '\r') {
                KeyString.pop_back();
            }

            return KeyString;
        }

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        void ImportKeyFromFile(std::string_view FileName) {
            ARL::ResourceWrapper KeyFile{ ARL::ResourceTraits::OpensslBIO{} };

            KeyFile.TakeOver(BIO_new_file(FileName.data(), "r"));
            if (KeyFile.IsValid() == false) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "BIO_new_file failed.");
            }

            ReleaseAndTakeOver(_ReadRSAFromBIO<__Type, __Format>(KeyFile));
        }

        template<RSAKeyType __Type, RSAKeyFormat __Format>
        void ImportKeyString(std::string_view KeyString) {
            ARL::ResourceWrapper TempMemory{ ARL::ResourceTraits::OpensslBIO{} };

            TempMemory.TakeOver(BIO_new(BIO_s_mem()));
            if (TempMemory.IsValid() == false) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "BIO_new failed.");
            }

            if (BIO_puts(TempMemory.Get(), KeyString.data()) <= 0) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "BIO_puts failed.");
            }

            TakeOver(_ReadRSAFromBIO<__Type, __Format>(TempMemory));
        }

        template<RSAKeyType __Type = RSAKeyType::PublicKey>
        size_t Encrypt(const void* lpFrom, size_t cbFrom, void* lpTo, int Padding) const {
            int BytesWritten;

            if (cbFrom > static_cast<size_t>(INT_MAX)) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "Length overflowed.");
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
                    throw ARL::OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(), "RSA_private_encrypt failed.");
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
                    throw ARL::OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(), "RSA_public_encrypt failed.");
                }
            }

            return BytesWritten;
        }

        template<RSAKeyType __Type = RSAKeyType::PrivateKey>
        size_t Decrypt(const void* lpFrom, size_t cbFrom, void* lpTo, int Padding) const {
            int BytesWritten;

            if (cbFrom > static_cast<size_t>(INT_MAX)) {
                throw ARL::Exception(__BASE_FILE__, __LINE__, "Length overflowed.");
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
                    throw ARL::OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(), "RSA_private_decrypt failed.")
                        .PushHint("Are your sure you DO provide a correct private key?");
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
                    throw ARL::OpensslError(__BASE_FILE__, __LINE__, ERR_get_error(), "RSA_public_decrypt failed.")
                        .PushHint("Are your sure you DO provide a correct public key?");
                }
            }

            return BytesWritten;
        }
    };

}

