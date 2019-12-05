#pragma once
#include <openssl/bio.h>
#include <openssl/rsa.h>

namespace ARL::ResourceTraits {

    struct OpensslBIO {
        using HandleType = BIO*;

        static inline const HandleType InvalidValue = nullptr;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) noexcept {
            BIO_free(Handle);
        }
    };

    struct OpensslBIOChain {
        using HandleType = BIO*;

        static inline const HandleType InvalidValue = nullptr;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) noexcept {
            BIO_free_all(Handle);
        }
    };

    struct OpensslBIGNUM {
        using HandleType = BIGNUM*;

        static inline const HandleType InvalidValue = nullptr;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) noexcept {
            BN_free(Handle);
        }
    };

    struct OpensslRSA {
        using HandleType = RSA*;

        static inline const HandleType InvalidValue = nullptr;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) noexcept {
            RSA_free(Handle);
        }
    };

}

