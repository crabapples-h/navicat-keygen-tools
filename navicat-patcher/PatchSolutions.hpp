#pragma once
#include "RSACipher.hpp"
#include "SystemObjectTraits.hpp"
#include "X64ImageInterpreter.hpp"
#include "CapstoneDisassembler.hpp"
#include "KeystoneAssembler.hpp"

//
//  Print memory data in [from, to) at least
//  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
//  NOTICE:
//      `base` must >= `from`
//
void PrintMemory(const void* from, const void* to, const void* base = nullptr);

class PatchSolution {
public:
    virtual void SetFile(const MapViewTraits::HandleType& FileViewHandle) = 0;
    virtual bool FindPatchOffset() = 0;
    virtual bool CheckKey(RSACipher* pCipher) const = 0;
    virtual void MakePatch(RSACipher* pCipher) const = 0;
    virtual ~PatchSolution() = default;
};

class PatchSolution0 : public PatchSolution {
private:
    static constexpr size_t InvalidOffset = static_cast<size_t>(-1);
    static const char Keyword[452];
    static constexpr size_t KeywordLength = 451;

    MapViewTraits::HandleType _$$_FileViewHandle;
    size_t _$$_PatchOffset;
public:
    PatchSolution0() noexcept;
    virtual void SetFile(const MapViewTraits::HandleType& FileViewHandle) noexcept override;
    virtual bool FindPatchOffset() noexcept override;
    virtual bool CheckKey(RSACipher* pCipher) const override;
    virtual void MakePatch(RSACipher* pCipher) const override;
};

class PatchSolution1 : public PatchSolution {
private:
    static constexpr size_t InvalidOffset = static_cast<size_t>(-1);
    static const uint8_t Keyword[0x188];
    static constexpr size_t KeywordLength = 0x188;

    MapViewTraits::HandleType _$$_FileViewHandle;
    size_t _$$_PatchOffset;
public:
    PatchSolution1() noexcept;
    virtual void SetFile(const MapViewTraits::HandleType& FileViewHandle) noexcept override;
    virtual bool FindPatchOffset() noexcept override;
    virtual bool CheckKey(RSACipher* cipher) const override;
    virtual void MakePatch(RSACipher* pCipher) const override;
};

class PatchSolution2 : public PatchSolution {
private:
    static constexpr size_t InvalidOffset = static_cast<size_t>(-1);
    static const char Keyword[1114];
    static constexpr size_t KeywordLength = 1114;
    static const uint8_t FunctionBeginByte[13];
    static const uint8_t FunctionHint[4];
    static constexpr size_t FunctionHintOffset = 0x2d2;
    static constexpr size_t FunctionSize = 0x938e;

    MapViewTraits::HandleType _$$_FileViewHandle;
    X64ImageInterpreter _$$_ImageInterpreter;
    CapstoneEngine _$$_CapstoneEngine;
    KeystoneEngine _$$_KeystoneEngine;

    size_t _$$_FunctionOffset;
    size_t _$$_KeywordOffset;
    size_t _$$_std_string_append_stub_Offset;

    bool IsStubHelperResolvedTo(const uint8_t* StubHelperProc, const char* Symbol) const;

public:
    PatchSolution2();
    virtual void SetFile(const MapViewTraits::HandleType& FileMapViewHandle) noexcept override;
    virtual bool FindPatchOffset() noexcept override;
    virtual bool CheckKey(RSACipher* pCipher) const override;
    virtual void MakePatch(RSACipher* pCipher) const override;
};