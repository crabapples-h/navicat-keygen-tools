#pragma once
#include <openssl/bio.h>
#include <openssl/rsa.h>

struct OpensslBIOTraits {
    using HandleType = BIO*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) noexcept {
        BIO_free(Handle);
    }
};

struct OpensslBIOChainTraits {
    using HandleType = BIO*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) noexcept {
        BIO_free_all(Handle);
    }
};

struct OpensslBNTraits {
    using HandleType = BIGNUM*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) noexcept {
        BN_free(Handle);
    }
};

struct OpensslRSATraits {
    using HandleType = RSA*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Releasor(const HandleType& Handle) noexcept {
        RSA_free(Handle);
    }
};

