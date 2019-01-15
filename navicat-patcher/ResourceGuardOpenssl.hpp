#pragma once
#include "ResourceGuard.hpp"

#if defined(HEADER_BIO_H)

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

#endif

#if defined(HEADER_BN_H)

struct OpensslBNTraits {
    using HandleType = BIGNUM*;
    static inline const HandleType InvalidValue = nullptr;
    static constexpr auto& Releasor = BN_free;
};

#endif

#if defined(HEADER_RSA_H)

struct OpensslRSATraits {
    using HandleType = RSA*;
    static inline const HandleType InvalidValue = nullptr;
    static constexpr auto& Releasor = RSA_free;
};

#endif

