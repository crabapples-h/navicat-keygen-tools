#pragma once
#include "ResourceGuard.hpp"
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

struct OpensslBIOTraits {
    using HandleType = BIO*;
    static const HandleType InvalidValue;
    static constexpr auto& Releasor = BIO_free;
};

inline const OpensslBIOTraits::HandleType
    OpensslBIOTraits::InvalidValue = nullptr;

struct OpensslBIOChainTraits {
    using HandleType = BIO*;
    static const HandleType InvalidValue;
    static constexpr auto& Releasor = BIO_free_all;
};

inline const OpensslBIOChainTraits::HandleType
    OpensslBIOChainTraits::InvalidValue = nullptr;

struct OpensslBNTraits {
    using HandleType = BIGNUM*;
    static const HandleType InvalidValue;
    static constexpr auto& Releasor = BN_free;
};

inline const OpensslBNTraits::HandleType
    OpensslBNTraits::InvalidValue = nullptr;

struct OpensslRSATraits {
    using HandleType = RSA*;
    static const HandleType InvalidValue;
    static constexpr auto& Releasor = RSA_free;
};

inline const OpensslRSATraits::HandleType
    OpensslRSATraits::InvalidValue = nullptr;

