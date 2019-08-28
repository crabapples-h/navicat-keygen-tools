#include "PatchSolutions.hpp"
#include <memory.h>

const char PatchSolution2::Keyword[1114] =
    "BIjWyoeRR0NBgkqnDZWxCgKCEAw1dqF3DTvOB91ZHwecJYFrdM1KEh"
    "1yVeRoGqSdLLGZGUlngig3OD5mMzs889IqWqqfHSeHMvzyg1p6UPCY"
    "nesxa9M2dDUrXHomRHOFHSfsbSXRFwt5GivtnJG9lLJHZ7XWeIQABi"
    "dKionYD3O6c9tvUAoDosUJAdQ1RaSXTzyETbHTRtnTPeLpO3EedGMs"
    "v3jG9yPcmmdYkddSeJRwn2raPJmnvdHScHUACw0sUNuosAqPaQbTQN"
    "PATDzcrnd1Sf8RIbUp4MQJFVJugPLVZbP53Gjtyyniqe5q75kva8Qm"
    "Hr1uOuXkVppe3cwECaGamupG43L1XfcpRjCMrxRep3s2VlbL01xmfz"
    "5cIhrj34iVmgZSAmIb8ZxiHPdp1oDMFkbNetZyWegqjAHQQ9eoSOTD"
    "bERbKEwZ5FLeLsbNAxfqsapB1XBvCavFHualx6bxVxuRQceh4z8kaZ"
    "iv2pOKbZQSJ2Dx5HEq0bYZ6y6b7sN9IaeDFNQwjzQn1K7k3XlYAPWC"
    "IvDe8Ln0FUe4yMNmuUhu5RTjxE05hUqtz1HjJvYQ9Es1VA6LflKQ87"
    "TwIXBNvfrcHaZ72QM4dQtDUyEMrLgMDkJBDM9wqIDps65gSlAz6eHD"
    "8tYWUttrWose0cH0yykVnqFzPtdRiZyZRfio6lGyK48mIC9z7T6MN3"
    "a7OaLZHZSwzcpQLcGi7M9q1wXLq4Ms1UvlwntB9FLHc63tHPpG8rhn"
    "XhZIk4QrSm4GYuEKQVHwku6ulw6wfggVL8FZPhoPCGsrb2rQGurBUL"
    "3lkVJ6RO9VGHcczDYomXqAJqlt4y9pkQIj9kgwTrxTzEZgMGdYZqsV"
    "4Bd5JjtrL7u3LA0N2Hq9Xvmmis2jDVhSQoUoGukNIoqng3SBsf0E7b"
    "4W0S1aZSSOJ90nQHQkQShE9YIMDBbNwIg2ncthwADYqibYUgIvJcK9"
    "89XHnYmZsdMWtt53lICsXE1vztR5WrQjSw4WXDiB31LXTrvudCB6vw"
    "kCQa4leutETpKLJ2bYaOYBdoiBFOwvf36YaSuRoY4SP2x1pWOwGFTg"
    "d90J2uYyCqUa3Q3iX52iigT4EKL2vJKdJ";

const uint8_t PatchSolution2::FunctionHeader[9] = {
    0x55,                   //  push rbp
    0x48, 0x89, 0xe5,       //  mov  rbp, rsp
    0x41, 0x57,             //  push r15
    0x41, 0x56,             //  push r14
    0x53,                   //  push rbx
};

PatchSolution2::PatchSolution2(const X64ImageInterpreter& Image) noexcept :
    pvt_Image(Image),
    pvt_Disassembler(CapstoneDisassembler::Create(CS_ARCH_X86, CS_MODE_64)),
    pvt_Assembler(KeystoneAssembler::Create(KS_ARCH_X86, KS_MODE_64)),
    pvt_FunctionOffset(X64ImageInterpreter::InvalidOffset),
    pvt_KeywordOffset(X64ImageInterpreter::InvalidOffset),
    pvt_StdStringAppendStubRva(X64ImageInterpreter::InvalidAddress)
{
    pvt_Disassembler.Option(CS_OPT_DETAIL, CS_OPT_ON);
}

bool PatchSolution2::FindPatchOffset() noexcept {
    auto FunctionOffset = X64ImageInterpreter::InvalidOffset;
    auto KeywordOffset = X64ImageInterpreter::InvalidOffset;
    auto StdStringAppendStubRva = X64ImageInterpreter::InvalidAddress;

    try {
        auto Sec__text = pvt_Image.ImageSection("__TEXT", "__text");
        auto Sec__const = pvt_Image.ImageSection("__TEXT", "__const");
        auto Sec__stubs = pvt_Image.ImageSection("__TEXT", "__stubs");
        auto SecView__text = pvt_Image.SectionView<uint8_t*>(Sec__text);
        auto SecView__const = pvt_Image.SectionView<uint8_t*>(Sec__const);
        auto SecView__stubs = pvt_Image.SectionView<uint8_t*>(Sec__stubs);

        KeywordOffset = pvt_Image.SearchSectionOffset("__TEXT", "__const", [](const uint8_t* p) {
            return memcmp(p, Keyword, sizeof(Keyword)) == 0;
        });

        auto KeywordRva = pvt_Image.OffsetToRva(KeywordOffset);

        auto Hint = pvt_Image.SearchSectionOffset("__TEXT", "__text", [Sec__text, SecView__text, KeywordRva](const uint8_t* p) {
            auto rip = (p - SecView__text) + Sec__text->addr + 4;
            auto off = *reinterpret_cast<const uint32_t*>(p);
            return rip + off == KeywordRva;
        }) - 0xc0;

        for (uint32_t i = 0; i < 0xc0; ++i) {
            if (memcmp(pvt_Image.ImageOffset(Hint + i), FunctionHeader, sizeof(FunctionHeader)) == 0) {
                FunctionOffset = Hint + i;
                break;
            }
        }

        if (FunctionOffset == X64ImageInterpreter::InvalidOffset) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::Exception(__FILE__, __LINE__, "Not found.");
        }

        pvt_Disassembler.SetContext(SecView__stubs, Sec__stubs->size, Sec__stubs->addr);
        while (pvt_Disassembler.Next()) {
            auto insn = pvt_Disassembler.GetInstruction();

            //
            // As far as I know, all stub functions have a pattern looking like:
            //     jmp qword ptr [RIP + xxxx]
            //
            if (strcasecmp(insn->mnemonic, "jmp") == 0 && insn->detail->x86.operands[0].type == X86_OP_MEM && insn->detail->x86.operands[0].mem.base == X86_REG_RIP) {
                uint64_t la_symbol_ptr_rva = pvt_Disassembler.GetContext().Address + insn->detail->x86.operands[0].mem.disp;
                uint32_t la_symbol_ptr_offset = pvt_Image.RvaToOffset(la_symbol_ptr_rva);
                if (la_symbol_ptr_offset == X64ImageInterpreter::InvalidOffset)
                    continue;

                uint64_t stub_helper_rva = *pvt_Image.ImageOffset<const uint64_t*>(la_symbol_ptr_offset);
                uint32_t stub_helper_offset = pvt_Image.RvaToOffset(stub_helper_rva);
                if (stub_helper_offset == X64ImageInterpreter::InvalidOffset)
                    continue;

                //
                // __ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc
                //     is the mangled name of "std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::append(char const*)",
                //     which is, as known as, "std::string::append(const char*)"
                // You can demangle it by c++flit
                // e.g.
                //     c++filt -_ '__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc'
                //
                if (nkg::IsResolvedTo(pvt_Image, pvt_Image.ImageOffset(stub_helper_offset), "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc")) {
                    auto StdStringAppendStubOffset = pvt_Disassembler.GetInstructionContext().pbOpcode - pvt_Image.ImageBase<const uint8_t*>();
                    StdStringAppendStubRva = pvt_Image.OffsetToRva(StdStringAppendStubOffset);
                    break;
                }
            }
        }

        if (StdStringAppendStubRva == X64ImageInterpreter::InvalidAddress) {
            // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
            throw nkg::Exception(__FILE__, __LINE__, "Not found.");
        }

        pvt_FunctionOffset = FunctionOffset;
        pvt_KeywordOffset = KeywordOffset;
        pvt_StdStringAppendStubRva = StdStringAppendStubRva;

        printf("[+] PatchSolution2 ...... Ready to apply.\n");
        printf("    Function offset = +0x%.8x\n", pvt_FunctionOffset);
        printf("    Keyword offset = +0x%.8x\n", pvt_KeywordOffset);
        printf("    std::string::append(const char*) RVA = 0x%.16llx\n", pvt_StdStringAppendStubRva);
        return true;
    } catch (...) {
        printf("[-] PatchSolution2 ...... Omitted.\n");
        return false;
    }
}

[[nodiscard]]
bool PatchSolution2::CheckKey(const RSACipher& RsaCipher) const noexcept {
    std::string PublicKeyPEM = RsaCipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

    PublicKeyPEM.erase(PublicKeyPEM.find("-----BEGIN PUBLIC KEY-----"), 26);
    PublicKeyPEM.erase(PublicKeyPEM.find("-----END PUBLIC KEY-----"), 24);
    {
        std::string::size_type pos = 0;
        while ((pos = PublicKeyPEM.find('\n', pos)) != std::string::npos) {
            PublicKeyPEM.erase(pos, 1);
        }
    }

    return PublicKeyPEM.length() == 0x188;
}

void PatchSolution2::MakePatch(const RSACipher& RsaCipher) const {
    if (pvt_FunctionOffset == X64ImageInterpreter::InvalidOffset ||
        pvt_KeywordOffset == X64ImageInterpreter::InvalidOffset ||
        pvt_StdStringAppendStubRva == X64ImageInterpreter::InvalidAddress)
    {
        // NOLINTNEXTLINE: allow exceptions that is not derived from std::exception
        throw nkg::Exception(__FILE__, __LINE__, "PatchSolution2 is not ready.");
    }

    //
    //  Prepare public key string
    //
    std::string PublicKeyPEM = RsaCipher.ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

    PublicKeyPEM.erase(PublicKeyPEM.find("-----BEGIN PUBLIC KEY-----"), 26);
    PublicKeyPEM.erase(PublicKeyPEM.find("-----END PUBLIC KEY-----"), 24);
    {
        std::string::size_type pos = 0;
        while ((pos = PublicKeyPEM.find('\n', pos)) != std::string::npos) {
            PublicKeyPEM.erase(pos, 1);
        }
    }

    //
    //  Prepare new function opcodes
    //
    uint64_t FunctionRVA = pvt_Image.OffsetToRva(pvt_FunctionOffset);
    uint64_t KeywordRVA = pvt_Image.OffsetToRva(pvt_KeywordOffset);

    char AssemblyCode[512] = {};
    sprintf(AssemblyCode,
            "push rbp;"
            "mov rbp, rsp;"
            "push r15;"
            "push r14;"
            "push rbx;"
            "sub rsp, 0x48;"

            "mov rbx, rdi;"

            "xor rax, rax;"                   // initialize std::string with null
            "mov qword ptr[rsp], rax;"
            "mov qword ptr[rsp + 0x8], rax;"
            "mov qword ptr[rsp + 0x10], rax;"

            "lea rdi, qword ptr[rsp];"
            "lea rsi, qword ptr[0x%.16llx];"  // filled with address to Keyword
            "call 0x%.16llx;"                 // filled with address to std::string::append(const char*)

            "mov rax, qword ptr[rsp];"
            "mov qword ptr[rbx], rax;"
            "mov rax, qword ptr[rsp + 0x8];"
            "mov qword ptr[rbx + 0x8], rax;"
            "mov rax, qword ptr[rsp + 0x10];"
            "mov qword ptr[rbx + 0x10], rax;"

            "mov rax, rbx;"
            "add rsp, 0x48;"
            "pop rbx;"
            "pop r14;"
            "pop r15;"
            "pop rbp;"
            "ret;",
            KeywordRVA,
            pvt_StdStringAppendStubRva
        );

    auto NewFunctionOpcode = pvt_Assembler.GenerateOpcode(AssemblyCode, FunctionRVA);

    auto pbFunctionPatch = pvt_Image.ImageOffset<uint8_t*>(pvt_FunctionOffset);
    auto pbKeywordPatch = pvt_Image.ImageOffset<uint8_t*>(pvt_KeywordOffset);

    puts("**************************************************************");
    puts("*                      PatchSolution2                        *");
    puts("**************************************************************");
    printf("@+0x%.8x\n", pvt_KeywordOffset);

    puts("Previous:");
    nkg::PrintMemory(pbKeywordPatch, pbKeywordPatch + sizeof(Keyword) - 1, pbKeywordPatch);

    memcpy(pbKeywordPatch, PublicKeyPEM.c_str(), PublicKeyPEM.length() + 1);  // with a null-terminator

    puts("After:");
    nkg::PrintMemory(pbKeywordPatch, pbKeywordPatch + sizeof(Keyword) - 1, pbKeywordPatch);




    puts("");
    printf("@+0x%.8x\n", pvt_FunctionOffset);

    puts("Previous:");
    nkg::PrintMemory(pbFunctionPatch, pbFunctionPatch + NewFunctionOpcode.size(), pbFunctionPatch);

    memcpy(pbFunctionPatch, NewFunctionOpcode.data(), NewFunctionOpcode.size());

    puts("After:");
    nkg::PrintMemory(pbFunctionPatch, pbFunctionPatch + NewFunctionOpcode.size(), pbFunctionPatch);

    puts("");
}
