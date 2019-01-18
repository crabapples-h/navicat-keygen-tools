#pragma once
#include "FileMapper.hpp"
#include "RSACipher.hpp"

#include <capstone/capstone.h>
#include "ExceptionCapstone.hpp"
#include "ResourceGuardCapstone.hpp"

#include "ImageInterpreter.hpp"

// lib required by capstone
#pragma comment(lib, "legacy_stdio_definitions.lib")
#if defined(_M_AMD64)
#pragma comment(lib, "capstone_static.lib")
#else
#pragma comment(lib, "capstone.lib")
#endif

#undef __BASE_FILE__
#define __BASE_FILE__ "PatchSolution.hpp"

class PatchSolution{
public:
    virtual void SetFile(FileMapper* pLibccFile) = 0;
    virtual bool CheckKey(RSACipher* pCipher) const = 0;
    virtual bool FindPatchOffset() noexcept = 0;
    virtual void MakePatch(RSACipher* pCipher) const = 0;
    virtual ~PatchSolution() {}
};

// PatchSolution0 will replace the RSA public key stored in main application.
class PatchSolution0 : public PatchSolution {
private:
    static const char Keyword[461];
    static constexpr size_t KeywordLength = 460;

    ImageInterpreter _TargetFile;
    off_t PatchOffset;
public:

    PatchSolution0() :
        PatchOffset(-1) {}

    virtual void SetFile(FileMapper* pMainApp) override {
        if (!_TargetFile.ParseImage(pMainApp->GetView<PVOID>(), true)) {
            throw Exception(__BASE_FILE__, __LINE__,
                            "Invalid PE file.");
        }
    }

    virtual bool CheckKey(RSACipher* pCipher) const override;

    // Return true if found, other return false
    virtual bool FindPatchOffset() noexcept override;

    // Make a patch based on an RSA private key given
    // Return true if success, otherwise return false
    virtual void MakePatch(RSACipher* cipher) const override;
};

// PatchSolution1 will replace the RSA public key stored in libcc.dll
class PatchSolution1 : public PatchSolution {
private:
    static const char* Keywords[5];
    static const size_t KeywordsLength[5];

    ImageInterpreter _TargetFile;
    off_t PatchOffsets[5];
public:
    PatchSolution1() :
        PatchOffsets{ -1, -1, -1, -1, -1 } {}

    virtual void SetFile(FileMapper* pLibccFile) override {
        if (!_TargetFile.ParseImage(pLibccFile->GetView<PVOID>(), true)) {
            throw Exception(__BASE_FILE__, __LINE__,
                            "Invalid PE file.");
        }
    }

    virtual bool CheckKey(RSACipher* cipher) const override;

    virtual bool FindPatchOffset() noexcept override;

    virtual void MakePatch(RSACipher* cipher) const override;
};

class PatchSolution2 : public PatchSolution {
private:
    static constexpr size_t KeywordsCount = 0x188;
    static const char KeywordsMeta[KeywordsCount + 1];
    static uint8_t Keywords[KeywordsCount][5];

    ImageInterpreter _TargetFile;
    off_t PatchOffsets[KeywordsCount];

    void BuildKeywords() noexcept;
public:
    PatchSolution2() {
        memset(PatchOffsets, -1, sizeof(PatchOffsets));
    }

    virtual void SetFile(FileMapper* pLibccFile) override {
        if (!_TargetFile.ParseImage(pLibccFile->GetView<PVOID>(), true)) {
            throw Exception(__BASE_FILE__, __LINE__,
                            "Invalid PE file.");
        }
    }

    virtual bool CheckKey(RSACipher* pCipher) const override;

    virtual bool FindPatchOffset() noexcept override;

    virtual void MakePatch(RSACipher* pCipher) const override;
};

class PatchSolution3 : public PatchSolution {
private:
    enum KeywordDataType {
        IMM_DATA,
        STRING_DATA,
    };

    struct KeywordType {
        uint8_t Data[8];
        size_t Length;
        KeywordDataType Type;
        bool NotRecommendedToModify;
    };

    struct BranchContext {
        const uint8_t* PtrOfCode;
        size_t SizeOfCode;
#if defined(_M_AMD64)
        uint64_t Rip;
#elif defined(_M_IX86)
        uint64_t Eip;
#else
#error "Unknown architecture."
#endif
    };

    struct PatchPointInfo {
        uint8_t* PtrToRelativeCode;
        uint64_t RelativeCodeRVA;
        uint8_t* PtrToPatch;
        size_t PatchSize;
        char* PtrToOriginalString;
        char* PtrToReplaceString;
    };

    static constexpr size_t KeywordsCount = 111;
    static const KeywordType Keywords[KeywordsCount];

    ResourceGuard<CapstoneHandleTraits> _CapstoneHandle;
    ImageInterpreter _TargetFile;
    mutable PatchPointInfo _Patches[KeywordsCount];

    bool CheckIfMatchPattern(cs_insn* PtrToInstruction) const;

    bool CheckIfFound(cs_insn* PtrToInstruction, 
                      size_t i) const;

    PatchPointInfo CreatePatchPoint(const uint8_t* PtrToCode, 
                                    cs_insn* PtrToInstruction, 
                                    size_t i) const;

    BranchContext GetJumpedBranch(const BranchContext& NotJumpedBranch,
                                  cs_insn* PtrToJmpInstruction) const;

    BranchContext HandleJcc(const BranchContext& NotJumpedBranch,
                            const BranchContext& JumpedBranch,
                            size_t i) const;
public:

    PatchSolution3();

    virtual void SetFile(FileMapper* pLibccFile) override {
        if (!_TargetFile.ParseImage(pLibccFile->GetView<PVOID>())) {
            throw Exception(__BASE_FILE__, __LINE__, 
                            "Invalid PE file.");
        }
    }
    
    virtual bool FindPatchOffset() noexcept override;
    virtual bool CheckKey(RSACipher* pCipher) const override;
    virtual void MakePatch(RSACipher* pCipher) const override;
    virtual ~PatchSolution3() = default;
};


