#pragma once
#include "FileMapper.hpp"
#include "RSACipher.hpp"

#include <capstone/capstone.h>
#include "ExceptionCapstone.hpp"
#include "ResourceGuardCapstone.hpp"

// lib required by capstone
#pragma comment(lib, "legacy_stdio_definitions.lib")
#pragma comment(lib, "capstone_static.lib")

#undef __BASE_FILE__
#define __BASE_FILE__ "PatchSolution.hpp"

class PatchSolution{
public:
    virtual void SetFile(FileMapper* pLibccFile) noexcept = 0;
    virtual bool CheckKey(RSACipher* pCipher) const = 0;
    virtual bool FindPatchOffset() noexcept = 0;
    virtual void MakePatch(RSACipher* pCipher) const = 0;
    virtual ~PatchSolution() {}
};

class PatchSolution3 : public PatchSolution {
private:
    enum KeywordDataType {
        IMM_DATA,
        STRING_DATA,
    };

    struct KeywordType {
        uint8_t data[8];
        size_t length;
        KeywordDataType type;
        bool NotRecommendedToModify;
    };

    struct BranchType {
        const uint8_t* PtrOfCode;
        size_t SizeOfCode;
        uint64_t Rip;
    };

    struct PatchPointType {
        uint8_t* PtrToRelativeCode;
        uint64_t RelativeCodeRVA;
        uint8_t* PtrToPatch;
        size_t PatchSize;
        char* pOriginalString;
        char* pReplaceString;
    };

    static constexpr size_t KeywordsCount = 111;
    static const KeywordType Keywords[KeywordsCount];

    ResourceGuard<CapstoneHandleTraits> _CapstoneHandle;
    FileMapper* _pTargetFile;
    mutable PatchPointType _Patches[KeywordsCount];

    bool CheckIfMatchPattern(cs_insn* pInstruction) const;
    bool CheckIfFound(cs_insn* pInstruction, size_t KeywordIndex) const;
    BranchType GetAnotherBranch(const BranchType& A, cs_insn* pInstruction) const;
    BranchType JudgeBranch(const BranchType A, const BranchType B, size_t CurrentKeywordIndex) const;
public:

    PatchSolution3();

    virtual void SetFile(FileMapper* pLibccFile) noexcept override {
        _pTargetFile = pLibccFile;
    }
    
    virtual bool FindPatchOffset() noexcept override;
    virtual bool CheckKey(RSACipher* pCipher) const override;
    virtual void MakePatch(RSACipher* pCipher) const override;
    virtual ~PatchSolution3() = default;
};


