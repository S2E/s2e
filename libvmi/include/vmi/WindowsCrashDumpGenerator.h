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

#ifndef VMI_BSOD_DEFS_H
#define VMI_BSOD_DEFS_H

#include <inttypes.h>

#include "FileProvider.h"
#include "RegisterProvider.h"
#include "ntddk.h"

namespace vmi {
namespace windows {

// Below are data types used to generate Windows kernel crash dumps
// Most of the stuff is taken from
// http://www.wasm.ru/print.php?article=dmp_format_en

static const uint32_t DUMP_HDR_SIGNATURE = 0x45474150;     //'EGAP'
static const uint32_t DUMP_HDR_DUMPSIGNATURE = 0x504D5544; //'PMUD'
static const uint32_t DUMP_KDBG_SIGNATURE = 0x4742444B;    //'GBDK'

static const uint32_t DUMP_HDR_DUMPSIGNATURE64 = 0x34365544; //'DU64'

// Page frame number
typedef uint32_t PFN_NUMBER;

struct PHYSICAL_MEMORY_RUN {
    PFN_NUMBER BasePage;
    PFN_NUMBER PageCount;
} __attribute__((packed));

struct PHYSICAL_MEMORY_RUN64 {
    uint64_t BasePage;
    uint64_t PageCount;
};

struct PHYSICAL_MEMORY_DESCRIPTOR {
    uint32_t NumberOfRuns;
    PFN_NUMBER NumberOfPages;
    PHYSICAL_MEMORY_RUN Run[1];
} __attribute__((packed));

struct PHYSICAL_MEMORY_DESCRIPTOR64 {
    uint32_t NumberOfRuns;
    uint64_t NumberOfPages;
    PHYSICAL_MEMORY_RUN64 Run[1];
};

struct DUMP_HEADER32 {
    /* 00 */ uint32_t Signature;
    /* 04 */ uint32_t ValidDump;
    /* 08 */ uint32_t MajorVersion;
    /* 0c */ uint32_t MinorVersion;
    /* 10 */ uint32_t DirectoryTableBase;
    /* 14 */ uint32_t PfnDataBase;
    /* 18 */ uint32_t PsLoadedModuleList;  // PLIST_ENTRY
    /* 1c */ uint32_t PsActiveProcessHead; // PLIST_ENTRY

    /* 20 */ uint32_t MachineImageType;
    /* 24 */ uint32_t NumberProcessors;
    /* 28 */ uint32_t BugCheckCode;
    /* 2c */ uint32_t BugCheckParameter1;
    /* 30 */ uint32_t BugCheckParameter2;
    /* 34 */ uint32_t BugCheckParameter3;
    /* 38 */ uint32_t BugCheckParameter4;
    /* 3c */ uint8_t VersionUser[32];
#if 0
/* 40 */    uint32_t Spare1;
/* 44 */    uint32_t Spare2;
/* 48 */    uint32_t Unknown1;
/* 4c */    uint32_t Unknown2;
/* 50 */    uint32_t Unknown3;
/* 54 */    uint32_t Unknown4;
/* 58 */    uint32_t Unknown5;
#endif
    /* 5c */ uint8_t PaeEnabled;
    uint8_t Reserved3[3];
    /* 60 */ uint32_t KdDebuggerDataBlock; // uint32_t
    union {
        PHYSICAL_MEMORY_DESCRIPTOR PhysicalMemoryBlock;
        uint8_t Reserved4[700];
    };

    union {
        CONTEXT32 Context;
        uint8_t Reserved5[1200];
    };

    EXCEPTION_RECORD32 ExceptionRecord;
    char Comment[128];
    uint8_t Reserved6[1768];
    uint32_t DumpType;
    uint32_t MinidumpFields;
    uint32_t SecondaryDataState;
    uint32_t ProductType;
    uint32_t SuiteMask;
    uint8_t Reserved7[4];
    uint64_t RequiredDumpSpace;
    uint8_t Reserved8[16];
    uint64_t SystemUpTime;
    uint64_t SystemTime;
    uint8_t Reserved9[56];
} __attribute__((packed));

// https://singularity.svn.codeplex.com/svn/base/Windows/Inc/Dump.h
// https://code.google.com/p/volatility/source/browse/branches/scudette/tools/windows/winpmem/executable/Dump.h?spec=svn2794&r=2790

struct DUMP_HEADER64 {
    uint32_t Signature;
    uint32_t ValidDump;
    uint32_t MajorVersion;
    uint32_t MinorVersion;
    uint64_t DirectoryTableBase;
    uint64_t PfnDataBase;
    uint64_t PsLoadedModuleList;  // PLIST_ENTRY
    uint64_t PsActiveProcessHead; // PLIST_ENTRY

    uint32_t MachineImageType;
    uint32_t NumberProcessors;
    uint32_t BugCheckCode;
    uint32_t align1;
    uint64_t BugCheckParameter1;
    uint64_t BugCheckParameter2;
    uint64_t BugCheckParameter3;
    uint64_t BugCheckParameter4;
    uint8_t VersionUser[32];

    uint64_t KdDebuggerDataBlock;
    union {
        PHYSICAL_MEMORY_DESCRIPTOR64 PhysicalMemoryBlock;
        uint8_t Reserved4[704];
    };

    union {
        CONTEXT64 Context;
        uint8_t Reserved5[3000];
    } __attribute__((packed));

    EXCEPTION_RECORD64 ExceptionRecord;
    uint32_t DumpType; // f98
    uint32_t align2;
    uint64_t RequiredDumpSpace;
    uint64_t SystemTime;   // fa8?
    uint8_t Comment[128];  // May not be present.
    uint64_t SystemUpTime; // fa0?

    uint32_t MiniDumpFields;
    uint32_t SecondaryDataState;
    uint32_t ProductType;
    uint32_t SuiteMask;
    uint32_t WriterStatus;
    uint8_t Unused1;
    uint8_t KdSecondaryVersion; // Present only for W2K3 SP1 and better
    uint8_t Unused[2];
    uint8_t _reserved0[4016];
} __attribute__((packed));
;

// Data Blocks
static const uint32_t DH_PHYSICAL_MEMORY_BLOCK = 25; // 0x19
static const uint32_t DH_CONTEXT_RECORD = 200;       // 0xc8
static const uint32_t DH_EXCEPTION_RECORD = 500;     // 0x1f4
static const uint32_t DH_DUMP_TYPE = 994;            // 0x3e2
static const uint32_t DH_REQUIRED_DUMP_SPACE = 1000; // 0x3e8
static const uint32_t DH_SUMMARY_DUMP_RECORD = 1024;

// Dump types
static const uint32_t DUMP_TYPE_TRIAGE = 4;
static const uint32_t DUMP_TYPE_SUMMARY = 2;
static const uint32_t DUMP_TYPE_COMPLETE = 1;

// Triage dump header
struct TRIAGE_DUMP_HEADER32 {
    uint32_t ServicePackBuild;      // 00
    uint32_t SizeOfDump;            // 04
    uint32_t ValidOffset;           // 08
    uint32_t ContextOffset;         // 0c
    uint32_t ExceptionOffset;       // 10
    uint32_t MmOffset;              // 14
    uint32_t UnloadedDriversOffset; // 18
    uint32_t PrcbOffset;            // 1c
    uint32_t ProcessOffset;         // 20
    uint32_t ThreadOffset;          // 24
    uint32_t Unknown1;              // 28
    uint32_t Unknown2;              // 2c
    uint32_t DriverListOffset;      // 30
    uint32_t DriverCount;           // 34
    uint32_t TriageOptions;         // 44
} __attribute__((packed));
;
// size 1ah *4

// Kernel summary dump header
struct SUMMARY_DUMP_HEADER {
    uint32_t Unknown1;   // 00
    uint32_t ValidDump;  // 04
    uint32_t Unknown2;   // 08
    uint32_t HeaderSize; // 0c
    uint32_t BitmapSize; // 10
    uint32_t Pages;      // 14
    uint32_t Unknown3;   // 18
    uint32_t Unknown4;   // 1c
} __attribute__((packed));
// size 20h

// Bitmap
#define RtlCheckBit(BMH, BP) ((((BMH)->Buffer[(BP) / 32]) >> ((BP) % 32)) & 0x1)

template <class T> struct PFUNC {
    T VirtualAddress;
    uint32_t ZeroField;
} __attribute__((packed));
;

// wdbgexts.h
struct KD_DEBUGGER_DATA_BLOCK32 {
    uint32_t Unknown1[4];
    uint32_t ValidBlock; // 'GBDK'
    uint32_t Size;       // 0x290
    PFUNC<uint32_t> _imp__VidInitialize;
    PFUNC<uint32_t> RtlpBreakWithStatusInstruction;
    uint32_t SavedContext;
    uint32_t Unknown2[3];
    PFUNC<uint32_t> KiCallUserMode;
    uint32_t Unknown3[2];
    PFUNC<uint32_t> PsLoadedModuleList;
    PFUNC<uint32_t> PsActiveProcessHead;
    PFUNC<uint32_t> PspCidTable;
    PFUNC<uint32_t> ExpSystemResourcesList;
    PFUNC<uint32_t> ExpPagedPoolDescriptor;
    PFUNC<uint32_t> ExpNumberOfPagedPools;
    PFUNC<uint32_t> KeTimeIncrement;
    PFUNC<uint32_t> KeBugCheckCallbackListHead;
    PFUNC<uint32_t> KiBugCheckData;
    PFUNC<uint32_t> IopErrorLogListHead;
    PFUNC<uint32_t> ObpRootDirectoryObject;
    PFUNC<uint32_t> ObpTypeObjectType;
    PFUNC<uint32_t> MmSystemCacheStart;
    PFUNC<uint32_t> MmSystemCacheEnd;
    PFUNC<uint32_t> MmSystemCacheWs;
    PFUNC<uint32_t> MmPfnDatabase;
    PFUNC<uint32_t> MmSystemPtesStart;
    PFUNC<uint32_t> MmSystemPtesEnd;
    PFUNC<uint32_t> MmSubsectionBase;
    PFUNC<uint32_t> MmNumberOfPagingFiles;
    PFUNC<uint32_t> MmLowestPhysicalPage;
    PFUNC<uint32_t> MmHighestPhysicalPage;
    PFUNC<uint32_t> MmNumberOfPhysicalPages;
    PFUNC<uint32_t> MmMaximumNonPagedPoolInBytes;
    PFUNC<uint32_t> MmNonPagedSystemStart;
    PFUNC<uint32_t> MmNonPagedPoolStart;
    PFUNC<uint32_t> MmNonPagedPoolEnd;
    PFUNC<uint32_t> MmPagedPoolStart;
    PFUNC<uint32_t> MmPagedPoolEnd;
    PFUNC<uint32_t> MmPagedPoolInfo;
    PFUNC<uint32_t> Unknown4;
    PFUNC<uint32_t> MmSizeOfPagedPoolInBytes;
    PFUNC<uint32_t> MmTotalCommitLimit;
    PFUNC<uint32_t> MmTotalCommittedPages;
    PFUNC<uint32_t> MmSharedCommit;
    PFUNC<uint32_t> MmDriverCommit;
    PFUNC<uint32_t> MmProcessCommit;
    PFUNC<uint32_t> MmPagedPoolCommit;
    PFUNC<uint32_t> Unknown5;
    PFUNC<uint32_t> MmZeroedPageListHead;
    PFUNC<uint32_t> MmFreePageListHead;
    PFUNC<uint32_t> MmStandbyPageListHead;
    PFUNC<uint32_t> MmModifiedPageListHead;
    PFUNC<uint32_t> MmModifiedNoWritePageListHead;
    PFUNC<uint32_t> MmAvailablePages;
    PFUNC<uint32_t> MmResidentAvailablePages;
    PFUNC<uint32_t> PoolTrackTable;
    PFUNC<uint32_t> NonPagedPoolDescriptor;
    PFUNC<uint32_t> MmHighestUserAddress;
    PFUNC<uint32_t> MmSystemRangeStart;
    PFUNC<uint32_t> MmUserProbeAddress;
    PFUNC<uint32_t> KdPrintCircularBuffer;
    PFUNC<uint32_t> KdPrintWritePointer;
    PFUNC<uint32_t> KdPrintWritePointer2;
    PFUNC<uint32_t> KdPrintRolloverCount;
    PFUNC<uint32_t> MmLoadedUserImageList;
    PFUNC<uint32_t> NtBuildLab;
    PFUNC<uint32_t> Unknown6;
    PFUNC<uint32_t> KiProcessorBlock;
    PFUNC<uint32_t> MmUnloadedDrivers;
    PFUNC<uint32_t> MmLastUnloadedDriver;
    PFUNC<uint32_t> MmTriageActionTaken;
    PFUNC<uint32_t> MmSpecialPoolTag;
    PFUNC<uint32_t> KernelVerifier;
    PFUNC<uint32_t> MmVerifierData;
    PFUNC<uint32_t> MmAllocateNonPagedPool;
    PFUNC<uint32_t> MmPeakCommitment;
    PFUNC<uint32_t> MmTotalCommitLimitMaximum;
    PFUNC<uint32_t> CmNtCSDVersion;
    PFUNC<uint32_t> MmPhysicalMemoryBlock; // PPHYSICAL_MEMORY_DESCRIPTOR*
    PFUNC<uint32_t> MmSessionBase;
    PFUNC<uint32_t> MmSessionSize;
    PFUNC<uint32_t> Unknown7;

} __attribute__((packed));
;

static const uint32_t PAE_ENABLED = (1 << 5);

struct BugCheckDescription {
    uint64_t code;
    uint64_t parameters[4];
    uint64_t guestHeader;
    uint64_t headerSize;

    BugCheckDescription() {
        headerSize = code = 0;
        parameters[0] = 0;
        parameters[1] = 0;
        parameters[2] = 0;
        parameters[3] = 0;
        guestHeader = 0;
    }
};

class WindowsCrashDumpGenerator {
private:
    uint64_t m_pKdDebuggerDataBlock;
    uint64_t m_pKpcrb;

    DBGKD_GET_VERSION64 m_kdVersion;

    std::shared_ptr<FileProvider> m_physicalMemory;
    std::shared_ptr<FileProvider> m_virtualMemory;
    X86RegisterProvider *m_registers;
    std::shared_ptr<FileProvider> m_out;

    std::vector<uint8_t> m_rawHeader;

    bool writeHeader(const CONTEXT32 &ctx, const BugCheckDescription &bugDesc);

    template <typename HEADER> bool writeMemoryData(HEADER *Header);

    template <typename HEADER, typename CONTEXT>
    bool writeHeader(HEADER *Header, const CONTEXT *context, const BugCheckDescription &bugDesc);

    WindowsCrashDumpGenerator(std::shared_ptr<FileProvider> virtualMemory, std::shared_ptr<FileProvider> physicalMemory,
                              X86RegisterProvider *registers, std::shared_ptr<FileProvider> out) {

        m_virtualMemory = virtualMemory;
        m_physicalMemory = physicalMemory;
        m_registers = registers;
        m_out = out;
    }

public:
    static std::shared_ptr<WindowsCrashDumpGenerator> get(std::shared_ptr<FileProvider> virtualMemory,
                                                          std::shared_ptr<FileProvider> physicalMemory,
                                                          X86RegisterProvider *registers,
                                                          std::shared_ptr<FileProvider> out) {
        return std::shared_ptr<WindowsCrashDumpGenerator>{
            new WindowsCrashDumpGenerator(virtualMemory, physicalMemory, registers, out)};
    }

    /* Windows XP */
    bool generate(uint64_t pKdDebuggerDataBlock, uint64_t pKpcrb, const DBGKD_GET_VERSION64 &kdVersion,
                  const CONTEXT32 &context, const BugCheckDescription &bugDesc);

    /* For newer OSes */
    bool generate(const BugCheckDescription &bugDesc, void *context, unsigned contextSize);
};
} // namespace windows
} // namespace vmi

#endif
