#include "PatchSolutions.hpp"
#include "CapstoneDisassembler.hpp"

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

const uint8_t PatchSolution2::FunctionBeginByte[13] = {
    0x55,                   //  push rbp
    0x48, 0x89, 0xe5,       //  mov  rbp, rsp
    0x41, 0x57,             //  push r15
    0x41, 0x56,             //  push r14
    0x53,                   //  push rbx
    0x48, 0x83, 0xec, 0x48  //  sub rsp, 0x48
};

const uint8_t PatchSolution2::FunctionHint[4] = {
    0x64, 0x77, 0x4b, 0x42
};

bool PatchSolution2::IsStubHelperResolvedTo(const uint8_t* StubHelperProc, const char* Symbol) const {
    CapstoneDisassembler Disassembler = _$$_CapstoneEngine.CreateDisassembler();
    Disassembler.SetContext(StubHelperProc, 10);

    if (!Disassembler.Next())
        return false;

    cs_insn* ins = Disassembler.GetInstruction();

    //
    // A stub helper proc must look like:
    //     push xxxxxx; (xxxxx is a imm value)
    //     jmp loc_xxxxx
    //
    if (strcasecmp(ins->mnemonic, "push") != 0 || ins->detail->x86.operands[0].type != X86_OP_IMM)
        return false;

    auto bind_opcodes_offset =
        static_cast<uint32_t>(ins->detail->x86.operands[0].imm);
    auto bind_opcodes_ptr =
        _$$_FileViewHandle.ConstViewAtOffset<uint8_t>(
            _$$_ImageInterpreter.DyldInfoCommand()->lazy_bind_off + bind_opcodes_offset
        );

    while ((*bind_opcodes_ptr & BIND_OPCODE_MASK) != BIND_OPCODE_DONE) {
        switch (*bind_opcodes_ptr & BIND_OPCODE_MASK) {
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:         // 0x10
            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:         // 0x30
            case BIND_OPCODE_SET_TYPE_IMM:                  // 0x50
            case BIND_OPCODE_DO_BIND:                       // 0x90
            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:   // 0xB0
                ++bind_opcodes_ptr;
                break;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:        // 0x20
            case BIND_OPCODE_SET_ADDEND_SLEB:               // 0x60
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:   // 0x70
            case BIND_OPCODE_ADD_ADDR_ULEB:                 // 0x80
            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:         // 0xA0
                while(*(++bind_opcodes_ptr) & 0x80);
                ++bind_opcodes_ptr;
                break;
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: // 0x40
                return strcmp(reinterpret_cast<const char*>(bind_opcodes_ptr + 1), Symbol) == 0;
            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:  // 0xC0
                //
                // This opcode is too rare to appear,
                // It is okay to dismiss this opcode
                //
                return false;
            default:
                return false;
        }
    }

    return false;
}

PatchSolution2::PatchSolution2() :
    _$$_FileViewHandle(MapViewTraits::InvalidValue),
    _$$_CapstoneEngine(CS_ARCH_X86, CS_MODE_64),
    _$$_KeystoneEngine(KS_ARCH_X86, KS_MODE_64),
    _$$_FunctionOffset(InvalidOffset),
    _$$_KeywordOffset(InvalidOffset),
    _$$_std_string_append_stub_Offset(InvalidOffset)
{
    _$$_CapstoneEngine.Option(CS_OPT_DETAIL, CS_OPT_ON);
}

void PatchSolution2::SetFile(const MapViewTraits::HandleType& FileViewHandle) noexcept {
    _$$_FileViewHandle = FileViewHandle;
    _$$_ImageInterpreter.LoadImage(FileViewHandle.View<void>());
    _$$_FunctionOffset = InvalidOffset;
    _$$_KeywordOffset = InvalidOffset;
    _$$_std_string_append_stub_Offset = InvalidOffset;
}

bool PatchSolution2::FindPatchOffset() noexcept {
    if (_$$_FileViewHandle == MapViewTraits::InvalidValue)
        return false;

    size_t FunctionOffset = InvalidOffset;
    size_t KeywordOffset = InvalidOffset;
    size_t std_string_append_stub_Offset = InvalidOffset;

    auto Sec__text = _$$_ImageInterpreter.SectionByName("__TEXT", "__text");
    auto Sec__const = _$$_ImageInterpreter.SectionByName("__TEXT", "__const");
    auto Sec__stubs = _$$_ImageInterpreter.SectionByName("__TEXT", "__stubs");
    if (Sec__text == nullptr || Sec__const == nullptr || Sec__stubs == nullptr)
        return false;
    auto SecView__text = _$$_FileViewHandle.ConstView<uint8_t>() + Sec__text->offset;
    auto SecView__const = _$$_FileViewHandle.ConstView<uint8_t>() + Sec__const->offset;
    auto SecView__stubs = _$$_FileViewHandle.ConstView<uint8_t>() + Sec__stubs->offset;

    for (uint64_t i = 0; i < Sec__text->size; ++i) {
        if (memcmp(SecView__text + i, FunctionHint, sizeof(FunctionHint)) == 0) {
            // we only allow that deviation is +-0x20
            for (uint64_t j = i - FunctionHintOffset - 0x20; j < i - FunctionHintOffset + 0x20; ++j) {
                if (memcmp(SecView__text + j,
                           FunctionBeginByte,
                           sizeof(FunctionBeginByte)) == 0) {
                    FunctionOffset = static_cast<size_t>(Sec__text->offset + j);
                    break;
                }
            }
            if (FunctionOffset != InvalidOffset)
                break;
        }
    }

    if (FunctionOffset == InvalidOffset) {
        printf("PatchSolution2 ...... Omitted.\n");
        return false;
    }

    for (uint64_t i = 0; i < Sec__const->size; ++i) {
        if (memcmp(SecView__const + i, Keyword, KeywordLength) == 0) {
            KeywordOffset = static_cast<size_t>(Sec__const->offset + i);
            break;
        }
    }

    if (KeywordOffset == InvalidOffset) {
        printf("PatchSolution2 ...... Omitted.\n");
        return false;
    }

    CapstoneDisassembler Disassembler = _$$_CapstoneEngine.CreateDisassembler();
    Disassembler.SetContext(SecView__stubs, Sec__stubs->size, Sec__stubs->addr);

    while (Disassembler.Next()) {
        auto ins = Disassembler.GetInstruction();
        //
        // As far as I know, all stub functions have a pattern looking like:
        //     jmp qword ptr [RIP + xxxx]
        //
        if (strcasecmp(ins->mnemonic, "jmp") == 0 && ins->detail->x86.operands[0].type == X86_OP_MEM && ins->detail->x86.operands[0].mem.base == X86_REG_RIP) {
            uint64_t la_symbol_ptr_rva = Disassembler.GetContext().Address + ins->detail->x86.operands[0].mem.disp;
            uint32_t la_symbol_ptr_offset = _$$_ImageInterpreter.AddressToOffset(la_symbol_ptr_rva);
            if (la_symbol_ptr_offset == X64ImageInterpreter::InvalidOffset)
                continue;

            uint64_t stub_helper_rva = *_$$_FileViewHandle.ConstViewAtOffset<uint64_t>(la_symbol_ptr_offset);
            uint32_t stub_helper_offset = _$$_ImageInterpreter.AddressToOffset(stub_helper_rva);
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
            if (IsStubHelperResolvedTo(_$$_FileViewHandle.ConstViewAtOffset<uint8_t>(stub_helper_offset),
                                       "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc")) {
                std_string_append_stub_Offset =
                    Disassembler.GetInstructionContext().Opcodes.ConstPtr - _$$_FileViewHandle.ConstView<uint8_t>();
                break;
            }
        }
    }

    if (std_string_append_stub_Offset == InvalidOffset) {
        printf("PatchSolution2 ...... Omitted.\n");
        return false;
    }

    _$$_FunctionOffset = FunctionOffset;
    _$$_KeywordOffset = KeywordOffset;
    _$$_std_string_append_stub_Offset = std_string_append_stub_Offset;
    printf("PatchSolution1 ...... Ready to apply.\n");
    printf("    Info: Target function offset = +0x%08zx\n", _$$_FunctionOffset);
    printf("    Info: Keyword offset = +0x%08zx\n", _$$_KeywordOffset);
    printf("    Info: std::string::append(const char*) offset = +%08zx\n", _$$_std_string_append_stub_Offset);
    return true;
}

bool PatchSolution2::CheckKey(RSACipher* pCipher) const {
    if (_$$_FileViewHandle == MapViewTraits::InvalidValue ||
        _$$_FunctionOffset == InvalidOffset ||
        _$$_KeywordOffset == InvalidOffset)
        throw Exception(__FILE__, __LINE__,
                        "PatchSolution2::MakePatch is not ready.");

    std::string PublicKeyPEM =
        pCipher->ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

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

void PatchSolution2::MakePatch(RSACipher* pCipher) const {
    if (_$$_FileViewHandle == MapViewTraits::InvalidValue ||
        _$$_FunctionOffset == InvalidOffset ||
        _$$_KeywordOffset == InvalidOffset ||
        _$$_std_string_append_stub_Offset == InvalidOffset)
    {
        throw Exception(__FILE__, __LINE__,
                        "Invalid patch offset.");
    }

    auto ViewPtr = _$$_FileViewHandle.View<uint8_t>();

    //
    //  Prepare public key string
    //
    std::string PublicKeyPEM =
        pCipher->ExportKeyString<RSAKeyType::PublicKey, RSAKeyFormat::PEM>();

    PublicKeyPEM.erase(PublicKeyPEM.find("-----BEGIN PUBLIC KEY-----"), 26);
    PublicKeyPEM.erase(PublicKeyPEM.find("-----END PUBLIC KEY-----"), 24);
    {
        std::string::size_type pos = 0;
        while ((pos = PublicKeyPEM.find('\n', pos)) != std::string::npos) {
            PublicKeyPEM.erase(pos, 1);
        }
    }

    assert(PublicKeyPEM.length() == 0x188);

    //
    //  Prepare new function opcodes
    //
    KeystoneAssembler Assembler = _$$_KeystoneEngine.CreateAssembler();

    uint64_t FunctionRVA = _$$_ImageInterpreter.OffsetToAddress(static_cast<uint32_t>(_$$_FunctionOffset));
    uint64_t KeywordRVA = _$$_ImageInterpreter.OffsetToAddress(static_cast<uint32_t>(_$$_KeywordOffset));
    uint64_t std_string_append_stub_RVA = _$$_ImageInterpreter.OffsetToAddress(static_cast<uint32_t>(_$$_std_string_append_stub_Offset));
    assert(FunctionRVA != X64ImageInterpreter::InvalidAddress);
    assert(KeywordRVA != X64ImageInterpreter::InvalidAddress);
    assert(std_string_append_stub_RVA != X64ImageInterpreter::InvalidAddress);

    char AssemblyCode[512] = {};
    sprintf(AssemblyCode,
            "push rbp;"
            "mov rbp, rsp;"
            "push r15;"
            "push r14;"
            "push rbx;"
            "sub rsp, 0x48;"

            "mov rbx, rdi;"

            "xor rax, rax;"
            "mov qword ptr[rsp], rax;"
            "mov qword ptr[rsp + 0x8], rax;"
            "mov qword ptr[rsp + 0x10], rax;"

            "lea rdi, qword ptr[rsp];"
            "lea rsi, qword ptr[0x%016llx];"  // filled with address to Keyword
            "call 0x%016llx;"                 // filled with address to std::string::append(const char*)

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
            std_string_append_stub_RVA);

    auto NewFunctionOpcodes = Assembler.OpCodes(AssemblyCode, FunctionRVA);

    puts("****************************");
    puts("*   Begin PatchSolution2   *");
    puts("****************************");
    printf("@+0x%08zx\n", _$$_KeywordOffset);
    puts("Previous:");
    PrintMemory(ViewPtr + _$$_KeywordOffset,
                ViewPtr + _$$_KeywordOffset + KeywordLength,
                ViewPtr);
    memcpy(ViewPtr + _$$_KeywordOffset,
           PublicKeyPEM.c_str(),
           PublicKeyPEM.length() + 1);  // with null-terminator

    puts("After:");
    PrintMemory(ViewPtr + _$$_KeywordOffset,
                ViewPtr + _$$_KeywordOffset + KeywordLength,
                ViewPtr);
    puts("");

    printf("@+0x%08zx\n", _$$_FunctionOffset);
    puts("Previous:");
    PrintMemory(ViewPtr + _$$_FunctionOffset,
                ViewPtr + _$$_FunctionOffset + NewFunctionOpcodes.size(),
                ViewPtr);

    memcpy(ViewPtr + _$$_FunctionOffset,
           NewFunctionOpcodes.data(),
           NewFunctionOpcodes.size());

    puts("After:");
    PrintMemory(ViewPtr + _$$_FunctionOffset,
                ViewPtr + _$$_FunctionOffset + NewFunctionOpcodes.size(),
                ViewPtr);
    puts("");
}

