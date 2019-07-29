#pragma once
#include "../common/Exception.hpp"
#include "../common/ResourceOwned.hpp"
#include "../common/RSACipher.hpp"
#include "ResourceTraitsUnix.hpp"
#include "X64ImageInterpreter.hpp"
#include "CapstoneDisassembler.hpp"
#include "KeystoneAssembler.hpp"

namespace nkg {
    //
    //  Print memory data in [from, to) at least
    //  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
    //  NOTICE:
    //      `base` must >= `from`
    //
    void PrintMemory(const void *from, const void *to, const void *base = nullptr);
    bool IsResolvedTo(const X64ImageInterpreter& Image, const void* StubHelperProc, const char *Symbol);
}

class PatchSolution {
public:

    [[nodiscard]]
    virtual bool FindPatchOffset() noexcept = 0;

    [[nodiscard]]
    virtual bool CheckKey(const RSACipher& RsaCipher) const noexcept = 0;

    virtual void MakePatch(const RSACipher& RsaCipher) const = 0;

    virtual ~PatchSolution() = default;
};

class PatchSolution0 : public PatchSolution {
private:

    static const char Keyword[452];

    const X64ImageInterpreter& pvt_Image;
    uint32_t pvt_PatchOffset;

public:

    explicit
    PatchSolution0(const X64ImageInterpreter& Image) noexcept;

    [[nodiscard]]
    // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
    virtual bool FindPatchOffset() noexcept override;

    [[nodiscard]]
    // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
    virtual bool CheckKey(const RSACipher& RsaCipher) const noexcept override;

    // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
    virtual void MakePatch(const RSACipher& RsaCipher) const override;
};

class PatchSolution1 : public PatchSolution {
private:

    static const uint8_t Keyword[0x188];

    const X64ImageInterpreter& pvt_Image;
    uint32_t pvt_PatchOffset;

public:

    explicit
    PatchSolution1(const X64ImageInterpreter& Image) noexcept;

    [[nodiscard]]
    // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
    virtual bool FindPatchOffset() noexcept override;

    [[nodiscard]]
    // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
    virtual bool CheckKey(const RSACipher& RsaCipher) const noexcept override;

    // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
    virtual void MakePatch(const RSACipher& RsaCipher) const override;
};

class PatchSolution2 : public PatchSolution {
private:

    static const char Keyword[1114];
    static const uint8_t FunctionHeader[9];

    const X64ImageInterpreter&  pvt_Image;
    CapstoneDisassembler        pvt_Disassembler;
    KeystoneAssembler           pvt_Assembler;
    uint32_t                    pvt_FunctionOffset;
    uint32_t                    pvt_KeywordOffset;
    uint64_t                    pvt_StdStringAppendStubRva;

public:

    explicit
    PatchSolution2(const X64ImageInterpreter& Image) noexcept;

    [[nodiscard]]
    // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
    virtual bool FindPatchOffset() noexcept override;

    [[nodiscard]]
    // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
    virtual bool CheckKey(const RSACipher& RsaCipher) const noexcept override;

    // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
    virtual void MakePatch(const RSACipher& RsaCipher) const override;
};

