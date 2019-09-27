#pragma once
#include <RSACipher.hpp>
#include "ImageInterpreter.hpp"
#include "CapstoneDisassembler.hpp"
#include "KeystoneAssembler.hpp"
#include "Misc.hpp"

namespace nkg {

    class PatchSolution {
    protected:
        
        static constexpr size_t InvalidOffset = -1;

    public:

        [[nodiscard]]
        virtual bool FindPatchOffset() noexcept = 0;

        [[nodiscard]]
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept = 0;

        virtual void MakePatch(const RSACipher& Cipher) const = 0;

        virtual ~PatchSolution() = default;
    };

    //
    // PatchSolution0 will replace the RSA public key stored in navicat.exe
    //
    class PatchSolution0 final : public PatchSolution {
    private:

        static const char Keyword[461];

        const ImageInterpreter& _Image;
        size_t _PatchOffset;

    public:

        PatchSolution0(const ImageInterpreter& Image) noexcept :
            _Image(Image),
            _PatchOffset(InvalidOffset) {}

        PatchSolution0(const ImageInterpreter* lpImage) noexcept :
            _Image(*lpImage),
            _PatchOffset(InvalidOffset) {}

        [[nodiscard]]
        virtual bool FindPatchOffset() noexcept override;

        [[nodiscard]]
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept override;

        virtual void MakePatch(const RSACipher& Cipher) const override;
    };

    //
    // PatchSolution1 will replace the RSA public key stored in libcc.dll
    //
    class PatchSolution1 final : public PatchSolution {
    private:

        static const char Keyword0[160 + 1];
        static const char Keyword1[4 + 1];
        static const char Keyword2[742 + 1];
        static const char Keyword3[4 + 1];
        static const char Keyword4[5 + 1];

        const ImageInterpreter& _Image;
        size_t _PatchOffset[5];
        size_t _PatchSize[5];

    public:

        PatchSolution1(const ImageInterpreter& Image) noexcept :
            _Image(Image),
            _PatchOffset{ InvalidOffset , InvalidOffset , InvalidOffset , InvalidOffset , InvalidOffset },
            _PatchSize{} {}

        PatchSolution1(const ImageInterpreter* lpImage) noexcept :
            _Image(*lpImage),
            _PatchOffset{ InvalidOffset , InvalidOffset , InvalidOffset , InvalidOffset , InvalidOffset },
            _PatchSize{} {}

        [[nodiscard]]
        virtual bool FindPatchOffset() noexcept override;

        [[nodiscard]]
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept override;

        virtual void MakePatch(const RSACipher& Cipher) const override;
    };

    //
    // PatchSolution2 will replace the RSA public key stored in libcc.dll
    //
    class PatchSolution2 final : public PatchSolution {
    private:

        static const char KeywordMeta[0x188 + 1];
        static const uint8_t Keyword[0x188][5];

        const ImageInterpreter& _Image;
        size_t _PatchOffset[0x188];

    public:

        PatchSolution2(const ImageInterpreter& Image) noexcept :
            _Image(Image),
            _PatchOffset{}
        {
            for (size_t i = 0; i < _countof(_PatchOffset); ++i) {
                _PatchOffset[i] = InvalidOffset;
            }
        }

        PatchSolution2(const ImageInterpreter* lpImage) noexcept :
            _Image(*lpImage),
            _PatchOffset{}
        {
            for (size_t i = 0; i < _countof(_PatchOffset); ++i) {
                _PatchOffset[i] = InvalidOffset;
            }
        }

        [[nodiscard]]
        virtual bool FindPatchOffset() noexcept override;

        [[nodiscard]]
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept override;

        virtual void MakePatch(const RSACipher& Cipher) const override;
    };

    //
    // PatchSolution3 will replace the RSA public key stored in libcc.dll
    //
    class PatchSolution3 final : public PatchSolution {
    private:

        using KeywordValueType = uint8_t[8];

        using KeywordSizeType = size_t;

        enum  KeywordTypeEnum { IMM_DATA, STRING_DATA };

        struct KeywordInfo {
            KeywordValueType Value;
            KeywordSizeType Size;
            KeywordTypeEnum Type;
            bool NotRecommendedToModify;
        };

        struct PatchInfo {
            uint64_t OpcodeRva;
            void* lpOpcode;
            void* lpPatch;
            size_t cbPatch;
            char* lpOriginalString;
            char* lpReplaceString;
        };

        static const KeywordInfo Keyword[111];

        const ImageInterpreter& _Image;
        CapstoneEngine          _Engine;
        mutable PatchInfo       _Patch[111];

        [[nodiscard]]
        static bool IsPrintable(const void* p, size_t s) noexcept;

        [[nodiscard]]
        bool CheckIfMatchPattern(const cs_insn* lpInsn) const noexcept;

        [[nodiscard]]
        bool CheckIfFound(const cs_insn* lpInsn, size_t KeywordIdx) const noexcept;

        [[nodiscard]]
        PatchInfo CreatePatchPoint(const void* lpOpcode, const cs_insn* lpInsn, size_t KeywordIdx) const noexcept;

        [[nodiscard]]
        CapstoneContext GetJumpedBranch(const CapstoneContext& Bifurcation, const cs_insn* lpJxxInsn) const;

        [[nodiscard]]
        CapstoneContext SelectBranch(const CapstoneContext& NotJumpedBranch, const CapstoneContext& JumpedBranch, size_t KeywordIdx) const;

    public:

        PatchSolution3(const ImageInterpreter& Image);

        PatchSolution3(const ImageInterpreter* lpImage);

        [[nodiscard]]
        virtual bool FindPatchOffset() noexcept override;

        [[nodiscard]]
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept override;

        virtual void MakePatch(const RSACipher& Cipher) const override;
    };

    //
    // PatchSolution3 will replace the RSA public key stored in libcc.dll
    // For Navicat Data Modeler 3
    //
    class PatchSolution4 : public PatchSolution {
    private:

        static const uint8_t KeywordA[0x188];
        static const uint8_t KeywordB[0x188];

        const ImageInterpreter& _Image;
        CapstoneEngine          _DisassemblyEngine;
        KeystoneEngine          _AssemblyEngine;
        uint8_t*                _pbPatchMachineCode;
        uint8_t*                _pbPatchNewPublicKey;
        std::vector<uint8_t>    _NewMachineCode;

    public:

        PatchSolution4(const ImageInterpreter& Image);

        PatchSolution4(const ImageInterpreter* lpImage);

        [[nodiscard]]
        virtual bool FindPatchOffset() noexcept override;

        [[nodiscard]]
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept override;

        virtual void MakePatch(const RSACipher& Cipher) const override;
    };
}
