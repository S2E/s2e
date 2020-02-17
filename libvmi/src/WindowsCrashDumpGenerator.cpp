///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include <assert.h>
#include <llvm/Support/raw_ostream.h>
#include <vector>

#include <vmi/WindowsCrashDumpGenerator.h>

namespace vmi {
namespace windows {

bool WindowsCrashDumpGenerator::writeHeader(const CONTEXT32 &ctx, const BugCheckDescription &bugDesc) {
    m_rawHeader.resize(0x1000);

    DUMP_HEADER32 *hdr = reinterpret_cast<DUMP_HEADER32 *>(&m_rawHeader[0]);

    // Set all dwords in the header to the magic value
    for (unsigned i = 0; i < 0x1000 / sizeof(uint32_t); i++) {
        uint32_t *dwords = reinterpret_cast<uint32_t *>(&m_rawHeader[0]);
        dwords[i] = DUMP_HDR_SIGNATURE;
    }

    hdr->ValidDump = DUMP_HDR_DUMPSIGNATURE;
    hdr->MajorVersion = m_kdVersion.MajorVersion;
    hdr->MinorVersion = m_kdVersion.MinorVersion;

    if (!m_registers->read(X86_CR3, &hdr->DirectoryTableBase)) {
        return false;
    }

    // Fetch KdDebuggerDataBlock
    // XXX: May break with windows versions
    hdr->KdDebuggerDataBlock = m_pKdDebuggerDataBlock;

    // Initialize bugcheck codes
    hdr->BugCheckCode = bugDesc.code;
    hdr->BugCheckParameter1 = bugDesc.parameters[0];
    hdr->BugCheckParameter2 = bugDesc.parameters[1];
    hdr->BugCheckParameter3 = bugDesc.parameters[2];
    hdr->BugCheckParameter4 = bugDesc.parameters[3];

    hdr->MachineImageType = 0x14c;
    hdr->NumberProcessors = 1;

    uint32_t cr4;
    if (!m_registers->read(X86_CR4, &cr4)) {
        return false;
    }

    hdr->PaeEnabled = (cr4 & PAE_ENABLED) ? 1 : 0;

    // Check KdDebuggerDataBlock
    KD_DEBUGGER_DATA_BLOCK32 KdDebuggerDataBlock;

    bool ok = m_virtualMemory->readb(&KdDebuggerDataBlock, sizeof(KdDebuggerDataBlock), hdr->KdDebuggerDataBlock);
    if (!ok) {
        llvm::errs() << "WindowsCrashDumpGenerator: Could not read "
                        "KD_DEBUGGER_DATA_BLOCK32\n";
        return false;
    }

    if (KdDebuggerDataBlock.ValidBlock != DUMP_KDBG_SIGNATURE ||
        KdDebuggerDataBlock.Size != sizeof(KdDebuggerDataBlock)) {
        // Invalid debugger data block
        llvm::errs() << "WindowsCrashDumpGenerator: KD_DEBUGGER_DATA_BLOCK32 is invalid\n";
        return false;
    }

    hdr->PfnDataBase = KdDebuggerDataBlock.MmPfnDatabase.VirtualAddress;
    hdr->PsLoadedModuleList = KdDebuggerDataBlock.PsLoadedModuleList.VirtualAddress;
    hdr->PsActiveProcessHead = KdDebuggerDataBlock.PsActiveProcessHead.VirtualAddress;

    // Get the physical memory descriptor
    uint32_t pMmPhysicalMemoryBlock;

    ok = m_virtualMemory->readb(&pMmPhysicalMemoryBlock, sizeof(pMmPhysicalMemoryBlock),
                                KdDebuggerDataBlock.MmPhysicalMemoryBlock.VirtualAddress);

    if (!ok) {
        llvm::errs() << "Could not read pMmPhysicalMemoryBlock\n";
        return false;
    }

    // Determine the number of runs
    uint32_t RunCount;
    ok = m_virtualMemory->readb(&RunCount, sizeof(RunCount), pMmPhysicalMemoryBlock);

    if (!ok) {
        llvm::errs() << "Could not read number of runs" << '\n';
        return false;
    }

    // Allocate enough memory for reading the whole structure
    size_t SizeOfMemoryDescriptor;
    if (RunCount == DUMP_HDR_SIGNATURE) {
        SizeOfMemoryDescriptor = sizeof(PHYSICAL_MEMORY_DESCRIPTOR);
    } else {
        SizeOfMemoryDescriptor =
            sizeof(PHYSICAL_MEMORY_DESCRIPTOR) - sizeof(PHYSICAL_MEMORY_RUN) + sizeof(PHYSICAL_MEMORY_RUN) * RunCount;
    }

    std::vector<uint8_t> MmPhysicalMemoryBlockVec;
    MmPhysicalMemoryBlockVec.resize(SizeOfMemoryDescriptor);
    PHYSICAL_MEMORY_DESCRIPTOR *MmPhysicalMemoryBlock =
        reinterpret_cast<PHYSICAL_MEMORY_DESCRIPTOR *>(&MmPhysicalMemoryBlockVec[0]);

    ok = m_virtualMemory->readb(&MmPhysicalMemoryBlock[0], SizeOfMemoryDescriptor, pMmPhysicalMemoryBlock);
    if (!ok) {
        llvm::errs() << "Could not read PHYSICAL_MEMORY_DESCRIPTOR\n";
        return false;
    }

    uint32_t *blocks = reinterpret_cast<uint32_t *>(&m_rawHeader[0]);

    assert(SizeOfMemoryDescriptor + DH_PHYSICAL_MEMORY_BLOCK * sizeof(uint32_t) <= m_rawHeader.size());

    memcpy(&blocks[DH_PHYSICAL_MEMORY_BLOCK], &MmPhysicalMemoryBlock[0], SizeOfMemoryDescriptor);

    // Initialize dump type & size
    blocks[DH_DUMP_TYPE] = DUMP_TYPE_COMPLETE;
    uint64_t dumpSpace = (MmPhysicalMemoryBlock->NumberOfPages << 12) + 0x1000;
    *((uint64_t *) &blocks[DH_REQUIRED_DUMP_SPACE]) = dumpSpace;

    llvm::outs() << "Writing " << sizeof(ctx) << " bytes of DH_CONTEXT_RECORD\n";

    memcpy(&blocks[DH_CONTEXT_RECORD], &ctx, sizeof(ctx));

    llvm::outs() << "Writing " << sizeof(ctx) << " bytes of DH_CONTEXT_RECORD" << '\n';
    memcpy(&blocks[DH_CONTEXT_RECORD], &ctx, sizeof(ctx));

    EXCEPTION_RECORD32 exception;
    memset(&exception, 0, sizeof(exception));
    exception.ExceptionCode = STATUS_BREAKPOINT;
    exception.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    exception.ExceptionRecord = 0;
    exception.ExceptionAddress = ctx.Eip;
    exception.NumberParameters = 0;

    llvm::outs() << "Writing " << sizeof(exception) << " bytes of DH_EXCEPTION_RECORD" << '\n';
    // Windows does not store exception parameters in the header
    memcpy(&blocks[DH_EXCEPTION_RECORD], &exception,
           sizeof(exception) - sizeof(uint32_t) * EXCEPTION_MAXIMUM_PARAMETERS);

    // Filling in the rest...
    hdr->SecondaryDataState = 0;
    hdr->ProductType = 0x1;
    hdr->SuiteMask = 0x110;

    return m_out->writeb(hdr, m_rawHeader.size(), 0);
}

template <typename HEADER> bool WindowsCrashDumpGenerator::writeMemoryData(HEADER *Header) {
    unsigned PagesWritten = 0;
    unsigned CurrentMemoryRun = 0;
    unsigned StartPageOffset = sizeof(*Header) >> 12;
    auto *ppmd = &Header->PhysicalMemoryBlock;

    while (CurrentMemoryRun < ppmd->NumberOfRuns) {
        if (ppmd->Run[CurrentMemoryRun].PageCount == DUMP_HDR_SIGNATURE ||
            ppmd->Run[CurrentMemoryRun].BasePage == DUMP_HDR_SIGNATURE) {
            llvm::outs() << "PHYSICAL_MEMORY_DESCRIPTOR corrupted." << '\n';
            return false;
        }

        llvm::outs() << "Processing run " << CurrentMemoryRun << '\n';

        uint32_t ProcessedPagesInCurrentRun = 0;
        while (ProcessedPagesInCurrentRun < ppmd->Run[CurrentMemoryRun].PageCount) {
            uint32_t physAddr = (ppmd->Run[CurrentMemoryRun].BasePage + ProcessedPagesInCurrentRun) * 0x1000;

            // s2e()->getDebugStream() << "Processing page " << std::dec <<
            // ProcessedPagesInCurrentRun
            //        << "(addr=0x" << std::hex << physAddr << '\n';

            uint8_t tempPage[0x1000];
            memset(tempPage, 0xDA, sizeof(tempPage));
            if (!m_physicalMemory->readb(tempPage, sizeof(tempPage), physAddr)) {
                llvm::errs() << "WindowsCrashDumpGenerator: could not read physical page " << physAddr << "\n";
            }

            m_out->write(tempPage, sizeof(tempPage), (PagesWritten + StartPageOffset) * sizeof(tempPage));

            PagesWritten++;
            ProcessedPagesInCurrentRun++;
        }

        CurrentMemoryRun++;
    }

    return true;
}

bool WindowsCrashDumpGenerator::generate(uint64_t pKdDebuggerDataBlock, uint64_t pKpcrb,
                                         const DBGKD_GET_VERSION64 &kdVersion, const CONTEXT32 &context,
                                         const BugCheckDescription &bugDesc) {
    m_kdVersion = kdVersion;
    m_pKdDebuggerDataBlock = pKdDebuggerDataBlock;
    m_pKpcrb = pKpcrb;

    if (!writeHeader(context, bugDesc)) {
        return false;
    }

    // Save the original context
    uint8_t originalContext[sizeof(CONTEXT32)];
    uint32_t KprcbProcessContextOffset = m_pKpcrb + offsetof(KPRCB32, ProcessorState.ContextFrame);
    if (!m_virtualMemory->readb(originalContext, sizeof(originalContext), KprcbProcessContextOffset)) {
        llvm::errs() << "WindowsCrashDumpGenerator: could not read KPCRB\n";
        return false;
    }

    // Write the new one to the KPRCB
    // WinDBG also expects it in the KPCRB, which is null by default
    if (!m_virtualMemory->writeb(&context, sizeof(CONTEXT32), KprcbProcessContextOffset)) {
        llvm::errs() << "Could not write the context to KPRCB" << '\n';
        return false;
    }

    // Dump the physical memory
    writeMemoryData(reinterpret_cast<DUMP_HEADER32 *>(&m_rawHeader[0]));

    // Restore the original context
    if (!m_virtualMemory->writeb(&originalContext, sizeof(CONTEXT32), KprcbProcessContextOffset)) {
        llvm::errs() << "Could not write the context to KPRCB" << '\n';
        return false;
    }

    return true;
}

template <typename HEADER, typename CONTEXT>
bool WindowsCrashDumpGenerator::writeHeader(HEADER *Header, const CONTEXT *context,
                                            const BugCheckDescription &bugDesc) {

    auto *ppmd = &Header->PhysicalMemoryBlock;

    Header->RequiredDumpSpace = sizeof(*Header);
    for (unsigned i = 0; i < ppmd->NumberOfRuns; ++i) {
        Header->RequiredDumpSpace += ppmd->Run[i].PageCount << 12;
    }

    Header->Context = *context;
    Header->BugCheckCode = bugDesc.code;
    Header->BugCheckParameter1 = bugDesc.parameters[0];
    Header->BugCheckParameter2 = bugDesc.parameters[1];
    Header->BugCheckParameter3 = bugDesc.parameters[2];
    Header->BugCheckParameter4 = bugDesc.parameters[3];

    return m_out->write(Header, sizeof(*Header), 0);
}

bool WindowsCrashDumpGenerator::generate(const BugCheckDescription &bugDesc, void *context, unsigned contextSize) {
    uint8_t buffer[0x2000];

    if (bugDesc.headerSize <= sizeof(buffer)) {
        if (!m_virtualMemory->readb(buffer, bugDesc.headerSize, bugDesc.guestHeader)) {
            return false;
        }
    }

    if (bugDesc.headerSize == 0x2000) {
        DUMP_HEADER64 *DumpHeader = reinterpret_cast<DUMP_HEADER64 *>(&buffer[0]);
        CONTEXT64 *DumpContext = static_cast<CONTEXT64 *>(context);

        assert(sizeof(*DumpHeader) == bugDesc.headerSize);
        assert(sizeof(*DumpContext) == contextSize);

        if (!writeHeader(DumpHeader, DumpContext, bugDesc)) {
            return false;
        }

        return writeMemoryData(DumpHeader);
    } else {
        DUMP_HEADER32 *DumpHeader = reinterpret_cast<DUMP_HEADER32 *>(&buffer[0]);
        CONTEXT32 *DumpContext = static_cast<CONTEXT32 *>(context);

        assert(sizeof(*DumpHeader) == bugDesc.headerSize);
        assert(sizeof(*DumpContext) == contextSize);

        if (!writeHeader(DumpHeader, DumpContext, bugDesc)) {
            return false;
        }

        return writeMemoryData(DumpHeader);
    }
}
} // namespace windows
} // namespace vmi
