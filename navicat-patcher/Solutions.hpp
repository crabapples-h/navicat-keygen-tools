#pragma once
#include "FileMapper.hpp"
#include "RSACipher.hpp"

namespace Patcher {

    class Solution {
    public:
        virtual void SetFile(FileMapper* pFile) = 0;
        virtual bool CheckKey(RSACipher* cipher) const = 0;
        virtual bool FindPatchOffset() = 0;
        virtual bool MakePatch(RSACipher* cipher) const = 0;
        virtual ~Solution() = default;
    };

    // Solution0 will replace the RSA public key stored in main application.
    class Solution0 : public Solution {
    private:
        static constexpr size_t KeywordLength = 451;
        static const char Keyword[KeywordLength + 1];

        FileMapper* pTargetFile;
        off_t PatchOffset;
    public:

        Solution0() noexcept :
                pTargetFile(nullptr),
                PatchOffset(-1) {}

        virtual void SetFile(FileMapper* pMainApp) noexcept override {
            pTargetFile = pMainApp;
        }

        // Solution0 does not have any requirements for an RSA-2048 key
        virtual bool CheckKey(RSACipher* cipher) const noexcept override {
            return true;
        }

        // Return true if found, other return false
        virtual bool FindPatchOffset() noexcept override;

        // Make a patch based on an RSA private key given
        // Return true if success, otherwise return false
        virtual bool MakePatch(RSACipher* cipher) const override;
    };

    // Solution1 will replace the RSA public key stored in main application.
    class Solution1 : public Solution {
    private:
        static constexpr size_t KeywordLength = 0x188;
        static const uint8_t Keyword[KeywordLength];

        FileMapper* pTargetFile;
        off_t PatchOffset;
    public:
        Solution1() :
                pTargetFile(nullptr),
                PatchOffset(-1) {}

        virtual void SetFile(FileMapper* pLibccFile) noexcept override {
            pTargetFile = pLibccFile;
        }

        // Solution1 has no requirements for an RSA-2048 key
        virtual bool CheckKey(RSACipher* cipher) const noexcept override {
            return true;
        }

        // Return true if found, otherwise return false
        virtual bool FindPatchOffset() noexcept override;

        // Make a patch based on an RSA private key given
        // Return true if success, otherwise return false
        virtual bool MakePatch(RSACipher* cipher) const override;
    };

}

