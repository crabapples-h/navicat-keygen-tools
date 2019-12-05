#pragma once
#include "RSACipher.hpp"
#include "Elf64Interpreter.hpp"
#include "CapstoneDisassembler.hpp"
#include "KeystoneAssembler.hpp"
#include <optional>

namespace nkg {

    class PatchSolution {
    protected:

        struct PatchMarkType {
            uint32_t Starter;
            uint8_t Data[0x188];
            uint32_t Terminator;
        };

        static constexpr uint32_t PatchMarkStarter = 0xdeadbeef;
        static constexpr uint32_t PatchMarkTerminator = 0xbeefdead;

        void SearchFreeSpace(std::map<Elf64_Off, Elf64_Xword>& SpaceMap, const Elf64Interpreter& Image);

    public:

        [[nodiscard]]
        virtual bool FindPatchOffset() noexcept = 0;

        [[nodiscard]]
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept = 0;

        virtual void MakePatch(const RSACipher& Cipher) const = 0;

        virtual ~PatchSolution() = default;
    };

    class PatchSolution0 final : public PatchSolution {
    private:

        const Elf64Interpreter&     m_Image;
        CapstoneEngine              m_DisassemblyEngine;
        KeystoneEngine              m_AssemblyEngine;

        const Elf64_Phdr*           m_RefSegment;
        std::optional<Elf64_Off>    m_PatchMarkOffset;
        std::optional<Elf64_Addr>   m_MachineCodeRva;
        std::optional<size_t>       m_MachineCodeSize;
        std::vector<uint8_t>        m_MachineCodeNew;

    public:

        PatchSolution0(const Elf64Interpreter& Image);

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool FindPatchOffset() noexcept override;

        [[nodiscard]]
        // NOLINTNEXTLINE: mark "virtual" explicitly for more readability
        virtual bool CheckKey(const RSACipher& Cipher) const noexcept override;

        virtual void MakePatch(const RSACipher& Cipher) const override;
    };
}

