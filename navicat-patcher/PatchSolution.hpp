#pragma once
#include "FileMapper.hpp"
#include "RSACipher.hpp"

#include <capstone/capstone.h>
#include "ExceptionCapstone.hpp"
#include "ResourceGuardCapstone.hpp"

#include "ImageInterpreter.hpp"

// lib required by capstone
#pragma comment(lib, "legacy_stdio_definitions.lib")
#pragma comment(lib, "capstone_static.lib")

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
        uint64_t Rip;
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

    bool CheckIfMatchPattern(cs_insn* pInstruction, size_t i) const;
    bool CheckIfFound(cs_insn* PtrToInstruction, size_t i) const;

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


