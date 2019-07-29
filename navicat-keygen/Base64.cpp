#include <vector>
#include <string>
#include <openssl/evp.h>
#include "../common/Exception.hpp"
#include "../common/ResourceOwned.hpp"
#include "../common/ResourceTraitsOpenssl.hpp"

std::string base64_encode(const std::vector<uint8_t>& bindata) {
    ResourceOwned b64(OpensslBIOTraits{}, BIO_new(BIO_f_base64()));
    if (b64.IsValid() == false) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "BIO_new failed.");
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    ResourceOwned mem(OpensslBIOTraits{}, BIO_new(BIO_s_mem()));
    if (mem.IsValid() == false) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "BIO_new failed.");
    }

    BIO_push(b64, mem);

    if (BIO_write(b64, bindata.data(), bindata.size()) != bindata.size()) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "BIO_write failed.");
    }

    if (BIO_flush(b64) != 1) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "BIO_flush failed.");
    }

    const char* data = nullptr;
    auto len = BIO_get_mem_data(mem, &data);

    BIO_pop(b64);

    return std::string(data, len);
}

std::vector<uint8_t> base64_decode(const std::string& ascdata) {
    ResourceOwned b64(OpensslBIOTraits{}, BIO_new(BIO_f_base64()));
    if (b64.IsValid() == false) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "BIO_new failed.");
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    ResourceOwned mem(OpensslBIOTraits{}, BIO_new_mem_buf(ascdata.c_str(), -1));
    if (mem.IsValid() == false) {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "BIO_new failed.");
    }

    BIO_push(b64, mem);

    std::vector<uint8_t> bindata(ascdata.length() / 4 * 3 + 1);
    bindata.resize(BIO_read(b64, bindata.data(), bindata.size()));

    BIO_pop(b64);

    return bindata;
}
