#pragma once
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string>

class OpenSSLException {
private:
    const unsigned long ErrorCode;
public:
    explicit OpenSSLException(unsigned long code) : ErrorCode(code) {}
    unsigned long GetErrorCode() const noexcept { return ErrorCode; }
    const char* GetErrorString() const noexcept { return ERR_error_string(ErrorCode, nullptr); }
};

template<typename _Type, void(_Type_free)(_Type*)>
class OpenSSLObject {
protected:
    _Type* _pObj;
public:
    // take over the object passed in
    explicit OpenSSLObject(_Type* pObj) noexcept : _pObj(pObj) {}

    OpenSSLObject(const OpenSSLObject<_Type, _Type_free>& other) = delete;

    OpenSSLObject(OpenSSLObject<_Type, _Type_free>&& other) noexcept : _pObj(other._pObj) {
        other._pObj = nullptr;
    }

    OpenSSLObject<_Type, _Type_free>&
    operator=(const OpenSSLObject<_Type, _Type_free>& other) = delete;

    OpenSSLObject<_Type, _Type_free>&
    operator=(_Type* other) noexcept {
        if (_pObj != other) {
            _Type_free(_pObj);
        }
        _pObj = other;
        return *this;
    }

    OpenSSLObject<_Type, _Type_free>&
    operator=(OpenSSLObject<_Type, _Type_free>&& other) noexcept {
        if (&other != this) {
            if (_pObj)
                _Type_free(_pObj);
            _pObj = other._pObj;
            other._pObj = nullptr;
        }
        return *this;
    }

    _Type* GetPointer() const noexcept {
        return _pObj;
    }

    ~OpenSSLObject() {
        if (_pObj) {
            _Type_free(_pObj);
            _pObj = nullptr;
        }
    }
};

class RSACipher {
private:
    OpenSSLObject<RSA, RSA_free> _RsaObj;

    explicit RSACipher(RSA* lpRsa) : _RsaObj(lpRsa) {}
public:

    RSACipher(const RSACipher&) = delete;
    RSACipher(RSACipher&&) = delete;
    RSACipher& operator=(const RSACipher&) = delete;
    RSACipher& operator=(RSACipher&&) = delete;

    enum class KeyType {
        PrivateKey,
        PublicKey
    };

    enum class KeyFormat {
        NotSpecified,
        PEM,
        PKCS1
    };

    static RSACipher* Create() {
        RSA* pObj = RSA_new();
        return pObj ? new RSACipher(pObj) : nullptr;
    }

    bool GenerateKey(int bits, unsigned int e = RSA_F4) {
        bool bSuccess = false;
        OpenSSLObject<BIGNUM, BN_free> bn_e(BN_new());

        if (!bn_e.GetPointer())
            return false;

        if (!BN_set_word(bn_e.GetPointer(), e))
            return false;

        if (!RSA_generate_key_ex(_RsaObj.GetPointer(), bits, bn_e.GetPointer(), nullptr))
            return false;

        return true;
    }

    template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
    bool ExportKeyToFile(const std::string& filename) {
        static_assert(
            _Type == KeyType::PrivateKey || (_Format == KeyFormat::PEM || _Format == KeyFormat::PKCS1),
            "Not supported format."
        );

        bool bSuccess = false;
        OpenSSLObject<BIO, BIO_free_all> bio_file(BIO_new_file(filename.c_str(), "w"));

        if (bio_file.GetPointer() == nullptr)
            return false;

        if (_Type == KeyType::PrivateKey) {
            bSuccess = PEM_write_bio_RSAPrivateKey(bio_file.GetPointer(), _RsaObj.GetPointer(), nullptr, nullptr, 0, nullptr, nullptr) != 0;
        } else {
            if (_Format == KeyFormat::PEM)
                bSuccess = PEM_write_bio_RSA_PUBKEY(bio_file.GetPointer(), _RsaObj.GetPointer()) != 0;
            if (_Format == KeyFormat::PKCS1)
                bSuccess = PEM_write_bio_RSAPublicKey(bio_file.GetPointer(), _RsaObj.GetPointer()) != 0;
        }

        return bSuccess;
    }

    template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
    std::string ExportKeyString() {
        static_assert(
            _Type == KeyType::PrivateKey || (_Format == KeyFormat::PEM || _Format == KeyFormat::PKCS1),
            "Not supported format."
        );

        std::string KeyString;
        OpenSSLObject<BIO, BIO_free_all> bio_mem(BIO_new(BIO_s_mem()));
        long len = 0;
        const char* lpdata = nullptr;

        if (bio_mem.GetPointer() == nullptr)
            return KeyString;

        if (_Type == KeyType::PrivateKey) {
            if (!PEM_write_bio_RSAPrivateKey(bio_mem.GetPointer(), _RsaObj.GetPointer(), nullptr, nullptr, 0, nullptr, nullptr))
                return KeyString;
        } else {
            if (_Format == KeyFormat::PEM) {
                if (!PEM_write_bio_RSA_PUBKEY(bio_mem.GetPointer(), _RsaObj.GetPointer()))
                    return KeyString;
            }
            if (_Format == KeyFormat::PKCS1) {
                if (!PEM_write_bio_RSAPublicKey(bio_mem.GetPointer(), _RsaObj.GetPointer()))
                    return KeyString;
            }
        }

        len = BIO_get_mem_data(bio_mem.GetPointer(), &lpdata);
        KeyString.assign(lpdata, static_cast<size_t>(len));
        return KeyString;
    }

    template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
    bool ImportKeyFromFile(const std::string& filename) {
        static_assert(
            _Type == KeyType::PrivateKey || (_Format == KeyFormat::PEM || _Format == KeyFormat::PKCS1),
            "Not supported format."
        );

        bool bSuccess = false;
        OpenSSLObject<BIO, BIO_free_all> bio_file(BIO_new_file(filename.c_str(), "r"));
        OpenSSLObject<RSA, RSA_free> newRsaObj(nullptr);

        if (bio_file.GetPointer() == nullptr)
            return false;

        if (_Type == KeyType::PrivateKey) {
            newRsaObj = PEM_read_bio_RSAPrivateKey(bio_file.GetPointer(), nullptr, nullptr, nullptr);
        } else {
            if (_Format == KeyFormat::PEM)
                newRsaObj = PEM_read_bio_RSA_PUBKEY(bio_file.GetPointer(), nullptr, nullptr, nullptr);
            if (_Format == KeyFormat::PKCS1)
                newRsaObj = PEM_read_bio_RSAPublicKey(bio_file.GetPointer(), nullptr, nullptr, nullptr);
        }

        if (newRsaObj.GetPointer()) {
            _RsaObj = static_cast<OpenSSLObject<RSA, RSA_free>&&>(newRsaObj);
            bSuccess = true;
        }

        return bSuccess;
    }

    template<KeyType _Type, KeyFormat _Format = KeyFormat::NotSpecified>
    bool ImportKeyString(const std::string& KeyString) {
        static_assert(
            _Type == KeyType::PrivateKey || (_Format == KeyFormat::PEM || _Format == KeyFormat::PKCS1),
            "Not supported format."
        );

        bool bSuccess = false;
        OpenSSLObject<BIO, BIO_free_all> bio_mem(BIO_new(BIO_s_mem()));
        OpenSSLObject<RSA, RSA_free> newRsaObj(nullptr);

        if (bio_mem.GetPointer() == nullptr)
            return false;

        BIO_puts(bio_mem.GetPointer(), KeyString.c_str());

        if (_Type == KeyType::PrivateKey) {
            newRsaObj = PEM_read_bio_RSAPrivateKey(bio_mem.GetPointer(), nullptr, nullptr, nullptr);
        } else {
            if (_Format == KeyFormat::PEM)
                newRsaObj = PEM_read_bio_RSA_PUBKEY(bio_mem.GetPointer(), nullptr, nullptr, nullptr);
            if (_Format == KeyFormat::PKCS1)
                newRsaObj = PEM_read_bio_RSAPublicKey(bio_mem.GetPointer(), nullptr, nullptr, nullptr);
        }

        if (newRsaObj.GetPointer()) {
            _RsaObj = static_cast<OpenSSLObject<RSA, RSA_free>&&>(newRsaObj);
            bSuccess = true;
        }

        return bSuccess;
    }

    template<KeyType _Type = KeyType::PublicKey>
    int Encrypt(const void* from, int len, void* to, int padding) {
        int write_bytes = 0;

        if (_Type == KeyType::PrivateKey) {
            write_bytes = RSA_private_encrypt(len,
                                              reinterpret_cast<const unsigned char*>(from),
                                              reinterpret_cast<unsigned char*>(to),
                                              _RsaObj.GetPointer(),
                                              padding);
        } else {
            write_bytes = RSA_public_encrypt(len,
                                             reinterpret_cast<const unsigned char*>(from),
                                             reinterpret_cast<unsigned char*>(to),
                                             _RsaObj.GetPointer(),
                                             padding);
        }

        if (write_bytes == -1)
            write_bytes = 0;
        return write_bytes;
    }

    template<KeyType _Type = KeyType::PrivateKey>
    int Decrypt(const void* from, int len, void* to, int padding) {
        int write_bytes = 0;

        if (_Type == KeyType::PrivateKey) {
            write_bytes = RSA_private_decrypt(len,
                                              reinterpret_cast<const unsigned char*>(from),
                                              reinterpret_cast<unsigned char*>(to),
                                              _RsaObj.GetPointer(),
                                              padding);
        } else {
            write_bytes = RSA_public_decrypt(len,
                                             reinterpret_cast<const unsigned char*>(from),
                                             reinterpret_cast<unsigned char*>(to),
                                             _RsaObj.GetPointer(),
                                             padding);
        }

        if (write_bytes == -1)
            write_bytes = 0;
        return write_bytes;
    }

};

