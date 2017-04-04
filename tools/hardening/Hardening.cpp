///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <fstream>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>

#include "Hardening.h"
#include "lib/Utils/Utils.h"

using namespace llvm;
using namespace s2etools;
using namespace vmi;

LogKey Hardening::TAG = LogKey("Hardening");

namespace {
cl::opt<std::string> InputBinary("binary", cl::desc("The binary file to harden"), cl::Required);

/* For now, only harden single instructions */
cl::opt<std::string> ProgramCounter("pc", cl::desc("Instruction to harden"), cl::Required);

cl::opt<unsigned> ByteCount("bytes",
                            cl::desc("How many bytes to overwrite. The last byte must be a return instruction."),
                            cl::init(1), cl::Optional);
}

Hardening::~Hardening() {
    if (m_inputBinary) {
        delete m_inputBinary;
    }

    if (m_fp) {
        delete m_fp;
    }
}

bool Hardening::initialize() {
    m_fp = FileSystemFileProvider::get(m_inputBinaryPath, true);
    if (!m_fp) {
        llvm::errs() << "Could not open " << m_inputBinaryPath << "\n";
        return false;
    }

    ExecutableFile *file = ExecutableFile::get(m_fp, false, 0);
    if (!file) {
        llvm::errs() << m_inputBinaryPath << " is not a valid executable file\n";
        return false;
    }

    m_inputBinary = dynamic_cast<PEFile *>(file);
    if (!m_inputBinary) {
        delete file;
        llvm::errs() << "Only PE files are supported for now\n";
        return false;
    }

    return true;
}

uint8_t *Hardening::assemble(const std::string &assembly, unsigned *size) {
    LOGINFO("Generating instrumentation\n");

    uint8_t *ret = NULL;
    uint8_t *section;
    std::unique_ptr<FileSystemFileProvider> binasm;
    struct stat s;

    char asmfile[] = "/tmp/XXXXXXXXXX";
    char binfile[] = "/tmp/XXXXXXXXXX";

    if (mkstemp(asmfile) < 0) {
        LOGERROR("Could not create temp file\n");
        goto err1;
    }

    if (mkstemp(binfile) < 0) {
        LOGERROR("Could not create temp bin file\n");
        goto err2;
    }

    {
        std::ofstream ofs(asmfile);
        ofs << assembly;
        ofs.close();
    }

    char cmdline[512];
    snprintf(cmdline, sizeof(cmdline), "nasm -o \"%s\" \"%s\"", binfile, asmfile);
    LOGDEBUG(cmdline << "\n");
    if (system(cmdline) < 0) {
        goto err3;
    }

    /* Read the content of the binary file */
    binasm = std::unique_ptr<FileSystemFileProvider>(FileSystemFileProvider::get(binfile, false));
    if (!binasm) {
        LOGERROR("Could not open " << binfile << "\n");
        goto err3;
    }

    if (binasm->stat(&s) < 0) {
        LOGERROR("Could not get file size of " << binfile << "\n");
        goto err3;
    }

    *size = s.st_size;

    if (*size & 0xfff) {
        *size &= ~0xfff;
        *size += 0x1000;
    }

    section = new uint8_t[*size];

    if (!binasm->readb(section, s.st_size, 0)) {
        LOGERROR("Could not read file " << binfile << "\n");
        delete[] section;
        goto err3;
    }

    ret = section;

err3:
    remove(binfile);
err2: // remove(asmfile);
err1:
    return ret;
}

uint64_t Hardening::getImportedFunction(const std::string &dll, const std::string &function) {
    Imports imports = m_inputBinary->getImports();
    Imports::const_iterator it = imports.find(dll);
    if (it == imports.end()) {
        LOGERROR("The binary does not import " << dll << "\n");
        return 0;
    }

    const ImportedSymbols &symbols = (*it).second;
    ImportedSymbols::const_iterator sit = symbols.find(function);

    if (sit == symbols.end()) {
        LOGERROR("The binary does not import " << dll << ":" << function << "\n");
        return 0;
    }

    uint64_t ret = (*sit).second.importTableLocation + m_inputBinary->getImageBase();
    LOGDEBUG(dll << ":" << function << " pc:" << hexval(ret) << "\n");

    return ret;
}

bool Hardening::harden(uint64_t pc) {
    LOGINFO("Hardening pc " << hexval(pc) << "\n");

    std::vector<uint8_t> bytes;
    bytes.resize(ByteCount);

    if (!m_inputBinary->read(&bytes[0], ByteCount, pc)) {
        LOGERROR("Could not read pc " << hexval(pc) << '\n');
        return false;
    }

    if (bytes.back() != 0xc3) {
        LOGERROR("Byte at " << hexval(pc + bytes.size() - 1) << " is not a return instruction\n");
        return false;
    }

#if 0
    uint32_t padding;
    if (!m_inputBinary->read(&padding, sizeof(padding), pc + 1)) {
        LOGERROR("Could not read 4 bytes at pc " << hexval(pc + 1) << '\n');
        return false;
    }

    if (padding != 0x90909090) {
        LOGERROR("Cannot overwrite ret instruction, not enough space after it\n");
        return false;
    }
#endif

    uint64_t TerminateProcess = getImportedFunction("kernel32.dll", "TerminateProcess");
    uint64_t MessageBoxA = getImportedFunction("user32.dll", "MessageBoxA");

    if (!TerminateProcess || !MessageBoxA) {
        return false;
    }

    windows::IMAGE_SECTION_HEADER freehdr;
    m_inputBinary->getFreeSectionHeader(freehdr, 0x1000);

    /**
     * This instrumetation checks that the return instruction points
     * to an instruction that follows a call.
     */
    std::stringstream ss;
    ss << "%define LOAD_BASE 0x" << std::hex << m_inputBinary->getImageBase() + freehdr.VirtualAddress << "\n"
       << "%define TERMINATE_PROCESS_PTR 0x" << TerminateProcess << "\n"
       << "%define MESSAGE_BOXA_PTR 0x" << MessageBoxA << "\n"
       << "[bits 32]\n"
          "\n"
          "ret_checker:\n";

    for (unsigned i = 0; i < bytes.size() - 1; ++i) {
        ss << "db 0x" << (unsigned) bytes[i] << "\n";
    }

    ss << "    push eax\n"
          "    mov eax, [esp+4]\n"
          "    sub eax, 5\n"
          "    cmp byte [eax], 0xe8 ; call instruction\n"
          "    jne failure\n"
          "    pop eax\n"
          "    ret\n"
          "\n"
          "failure:\n"
          //"    int3\n"
          "    jmp PrintAndExit\n"
          "get_real_address:\n"
          "    call myself\n"
          "    myself:\n"
          "    pop eax\n"
          "    sub eax, myself\n"
          "    add eax, [esp + 4]\n"
          "    ret 4\n"
          "TerminateProcess:\n"
          "    push dword (TERMINATE_PROCESS_PTR - LOAD_BASE)\n"
          "    call get_real_address\n"
          "    jmp [eax]\n"
          "MessageBoxA:\n"
          "    push dword (MESSAGE_BOXA_PTR - LOAD_BASE)\n"
          "    call get_real_address\n"
          "    jmp [eax]\n"
          "PrintAndExit:\n"
          "    push mymsg\n"
          "    call get_real_address\n"
          "    push dword 0x40\n" // MB_ICONINFORMATION
          "    push dword 0\n"
          "    push eax\n"
          "    push dword 0\n"
          "    call MessageBoxA\n"
          "    push dword 0x1\n"
          "    push dword 0xffffffff\n"
          "    call TerminateProcess\n"
          "mymsg: db \"Detected exploit attempt\", 0";

    unsigned sectionSize;
    uint8_t *section = assemble(ss.str(), &sectionSize);

    if (!section) {
        return false;
    }

    windows::IMAGE_SECTION_HEADER *hdr;
    hdr = m_inputBinary->appendSection(".inj", section, sectionSize);
    if (!hdr) {
        LOGERROR("Could not inject section into " << m_inputBinaryPath << "\n");
        return false;
    }

    assert(hdr->VirtualAddress == freehdr.VirtualAddress);

    llvm::outs() << "RVA of new section: " << hexval(hdr->VirtualAddress) << "\n";

    struct {
        uint8_t jmp_opcode;
        uint32_t jmp_offset;
    } __attribute__((packed)) op;

    uint32_t target = m_inputBinary->getImageBase() + hdr->VirtualAddress;
    llvm::outs() << "Jump target: " << hexval(target) << "\n";

    op.jmp_opcode = 0xe9;
    op.jmp_offset = target - pc - 5;

    if (!m_inputBinary->write(&op, sizeof(op), pc)) {
        LOGERROR("Could not write byte to pc " << hexval(pc) << '\n');
        return false;
    }

    return false;
}

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, (char **) argv, " hardening");

    if (!llvm::sys::fs::exists(InputBinary)) {
        llvm::errs() << InputBinary << " does not exist\n";
        return -1;
    }

    Hardening hard(InputBinary);
    if (!hard.initialize()) {
        return -1;
    }

    uint64_t pc = strtol(ProgramCounter.c_str(), NULL, 0);
    if (!hard.harden(pc)) {
        return -1;
    }

    return 0;
}
