#pragma once
#include "ResourceGuard.hpp"
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

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

