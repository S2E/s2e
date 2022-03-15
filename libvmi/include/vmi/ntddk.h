///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014, Cyberhaven
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

#ifndef _NT_DDK_H_

#define _NT_DDK_H_

namespace vmi {
namespace windows {

typedef uint8_t BOOLEAN;
typedef uint8_t UCHAR;
typedef int8_t CCHAR;
typedef uint16_t WORD;
typedef uint16_t USHORT;
typedef uint16_t CSHORT;
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef uint32_t UINT;
typedef uint32_t HANDLE;
typedef uint64_t ULONG64;

/****************************************************************/
/****************************************************************/
/****************************************************************/

/*typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
}UNICODE_STRING, *PUNICODE_STRING;*/

struct UNICODE_STRING32 {
    uint16_t Length;
    uint16_t MaximumLength;
    uint32_t Buffer;
};

struct UNICODE_STRING64 {
    uint16_t Length;
    uint16_t MaximumLength;
    uint64_t Buffer;
};

struct BINARY_DATA32 {
    uint16_t Length;
    uint32_t Buffer;
} __attribute__((packed));

struct LIST_ENTRY32 {
    uint32_t Flink;
    uint32_t Blink;
};

struct LIST_ENTRY64 {
    uint64_t Flink;
    uint64_t Blink;
};

#define CONTAINING_RECORD32(address, type, field) \
    ((uint32_t) ((uint32_t) (address) - (uint32_t) (uint64_t) (&((type *) 0)->field)))

typedef int32_t NTSTATUS; // MUST BE SIGNED

#define NT_SUCCESS(Status)     ((NTSTATUS) (Status) >= 0)
#define NT_INFORMATION(Status) ((ULONG) (Status) >> 30 == 1)
#define NT_WARNING(Status)     ((ULONG) (Status) >> 30 == 2)
#define NT_ERROR(Status)       ((ULONG) (Status) >> 30 == 3)

typedef struct _MODULE_ENTRY32 {
    LIST_ENTRY32 LoadOrder;
    LIST_ENTRY32 MemoryOrder;
    LIST_ENTRY32 InitializationOrder;
    uint32_t BaseAddress;
    uint32_t EntryPoint;
    uint32_t ImageSize;
    UNICODE_STRING32 DriverPath;
    UNICODE_STRING32 DriverName;
} __attribute__((packed)) MODULE_ENTRY32, *PMODULE_ENTRY32;

struct MODULE_ENTRY64 {
    LIST_ENTRY64 LoadOrder;
    LIST_ENTRY64 MemoryOrder;
    LIST_ENTRY64 InitializationOrder;
    uint64_t BaseAddress;
    uint64_t EntryPoint;
    uint32_t ImageSize;
    UNICODE_STRING64 DriverPath;
    UNICODE_STRING64 DriverName;
};

typedef struct _DRIVER_OBJECT32 {
    uint16_t Type;
    uint16_t Size;

    uint32_t DeviceObject; // PVOID
    uint32_t Flags;

    uint32_t DriverStart;     // PVOID
    uint32_t DriverSize;      // ULONG
    uint32_t DriverSection;   // PVOID
    uint64_t DriverExtension; // PDRIVER_EXTENSION
    UNICODE_STRING32 DriverName;

    uint32_t HardwareDatabase; // PUNICODE_STRING
    uint32_t FastIoDispatch;
    uint32_t DriverInit;
    uint32_t DriverStartIo;
    uint32_t DriverUnload;
    uint32_t MajorFunction[28];
} __attribute__((packed)) DRIVER_OBJECT32, *PDRIVER_OBJECT32;

// Pointers should be aligned on 64-bits boundaries
struct DRIVER_OBJECT64 {
    uint16_t Type;
    uint16_t Size;

    uint64_t DeviceObject; // PVOID
    uint32_t Flags;

    uint64_t DriverStart;     // PVOID
    uint32_t DriverSize;      // ULONG
    uint64_t DriverSection;   // PVOID
    uint64_t DriverExtension; // PDRIVER_EXTENSION
    UNICODE_STRING64 DriverName;

    uint64_t HardwareDatabase; // PUNICODE_STRING
    uint64_t FastIoDispatch;
    uint64_t DriverInit;
    uint64_t DriverStartIo;
    uint64_t DriverUnload;
    uint64_t MajorFunction[28];
};

extern const char *s_irpMjArray[];

// KPCR is at fs:1c
// This is only valid for XP (no ASLR)
//#define KPCR_ADDRESS  0xFFDFF000

// Offset of the pointer to KPCR relative to the fs register
static const uint32_t KPCR_FS_OFFSET = 0x1c;

// Offset of the DBGKD_GET_VERSION32 data structure in the KPCR
static const uint32_t KPCR_KDVERSION32_OFFSET = 0x34;

// Offset of the KPRCB in the KPCR
static const uint32_t KPCR_KPRCB_OFFSET = 0x120;
static const uint32_t KPCR_KPRCB_PTR_OFFSET = 0x20;

// Offset of the current thread in the FS register
static const uint32_t FS_CURRENT_THREAD_OFFSET = 0x124;

// Offset of the pointer to the EPROCESS in the ETHREAD structure
static const uint32_t ETHREAD_PROCESS_OFFSET_VISTA = 0x48;
static const uint32_t ETHREAD_PROCESS_OFFSET_XP = 0x44;

static const uint32_t EPROCESS_ACTIVE_PROCESS_LINK_XP = 0x88;

//#define KD_VERSION_BLOCK (KPCR_ADDRESS + 0x34)
static const uint32_t PS_LOADED_MODULE_LIST_OFFSET = 0x70; // Inside the kd version block

static const uint32_t BUILD_WINXP = 2600;
static const uint32_t BUILD_LONGHORN = 5048;

//#define KPRCB_OFFSET 0xFFDFF120
static const uint32_t IRQL_OFFSET = 0xFFDFF124;
static const uint32_t PEB_OFFSET = 0x7FFDF000;
typedef uint32_t KAFFINITY;

typedef struct _DBGKD_GET_VERSION32 {
    uint16_t MajorVersion; // 0xF == Free, 0xC == Checked
    uint16_t MinorVersion;
    uint16_t ProtocolVersion;
    uint16_t Flags; // DBGKD_VERS_FLAG_XXX
    uint32_t KernBase;
    uint32_t PsLoadedModuleList;
    uint16_t MachineType;
    uint16_t ThCallbackStack;
    uint16_t NextCallback;
    uint16_t FramePointer;
    uint32_t KiCallUserMode;
    uint32_t KeUserCallbackDispatcher;
    uint32_t BreakpointWithStatus;
    uint32_t Reserved4;
} __attribute__((packed)) DBGKD_GET_VERSION32, *PDBGKD_GET_VERSION32;

typedef struct _DBGKD_GET_VERSION64 {
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint8_t ProtocolVersion;
    uint8_t KdSecondaryVersion;
    uint16_t Flags;
    uint16_t MachineType;
    uint8_t MaxPacketType;
    uint8_t MaxStateChange;
    uint8_t MaxManipulate;
    uint8_t Simulation;
    uint16_t Unused[1];
    uint64_t KernBase;
    uint64_t PsLoadedModuleList;
    uint64_t DebuggerDataList;
} __attribute__((packed)) DBGKD_GET_VERSION64, *PDBGKD_GET_VERSION64;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    uint32_t DllBase;
    uint32_t EntryPoint;
    uint32_t SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    uint32_t Flags;
    uint16_t LoadCount;
    uint16_t TlsIndex;
    union {
        LIST_ENTRY32 HashLinks;
        struct {
            uint32_t SectionPointer;
            uint32_t CheckSum;
        };
    };
    union {
        uint32_t TimeDateStamp;
        uint32_t LoadedImports;
    };
    uint32_t EntryPointActivationContext;
    uint32_t PatchInformation;
} __attribute__((packed)) LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA32 {
    uint32_t Length;
    uint32_t Initialized;
    uint32_t SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    uint32_t EntryInProgress;
} __attribute__((packed)) PEB_LDR_DATA32;

typedef struct _PEB32 {
    uint8_t Unk1[0x8];
    uint32_t ImageBaseAddress;
    uint32_t Ldr; /* PEB_LDR_DATA */
} __attribute__((packed)) PEB32;

typedef struct _KPROCESS32_XP {
    uint8_t Unk1[0x18];
    uint32_t DirectoryTableBase;
    uint8_t Unk2[0x50];
} __attribute__((packed)) KPROCESS32_XP;

typedef struct _EPROCESS32_XP {
    KPROCESS32_XP Pcb;
    uint32_t ProcessLock;
    uint64_t CreateTime;
    uint64_t ExitTime;
    uint32_t RundownProtect;
    uint32_t UniqueProcessId;
    LIST_ENTRY32 ActiveProcessLinks;
    uint8_t Unk2[0xE4];
    uint8_t ImageFileName[16]; // offset 0x174
    uint32_t Unk3[11];
    uint32_t Peb;
} __attribute__((packed)) EPROCESS32_XP;

typedef struct _KPROCESS32_VISTA {
    uint8_t Unk1[0x10];
    LIST_ENTRY32 ProfileListHead;
    uint32_t DirectoryTableBase;
    uint8_t Unk2[0x64];
} __attribute__((packed)) KPROCESS32_VISTA;

typedef struct _EPROCESS32_VISTA {
    KPROCESS32_VISTA Pcb;
    uint64_t ProcessLock;
    uint64_t CreateTime;
    uint64_t ExitTime;
    uint32_t RundownProtect;
    uint32_t UniqueProcessId;
    LIST_ENTRY32 ActiveProcessLinks;
    uint8_t Unk2[0xa4];
    uint8_t ImageFileName[16]; // offset 14c
    uint32_t Unk3[11];
    uint32_t Peb;
} __attribute__((packed)) EPROCESS32_VISTA;

typedef struct _KAPC_STATE32 {
    LIST_ENTRY32 ApcListHead[2];
    uint32_t Process; /* Ptr to (E)KPROCESS */
    uint8_t KernelApcInProgress;
    uint8_t KernelApcPending;
    uint8_t UserApcPending;
} __attribute__((packed)) KAPC_STATE32;

typedef struct _KTHREAD32 {
    uint8_t Unk1[0x18];
    uint32_t InitialStack;
    uint32_t StackLimit;
    uint8_t Unk2[0x14];
    KAPC_STATE32 ApcState;

    uint8_t Unk3[0x164];

    LIST_ENTRY32 ThreadListEntry;

} __attribute__((packed)) KTHREAD32;

/*
+0x000 Header           : _DISPATCHER_HEADER
   +0x010 MutantListHead   : _LIST_ENTRY
   +0x018 InitialStack     : Ptr32 Void
   +0x01c StackLimit       : Ptr32 Void
   +0x020 Teb              : Ptr32 Void
   +0x024 TlsArray         : Ptr32 Void
   +0x028 KernelStack      : Ptr32 Void
   +0x02c DebugActive      : UChar
   +0x02d State            : UChar
   +0x02e Alerted          : [2] UChar
   +0x030 Iopl             : UChar
   +0x031 NpxState         : UChar
   +0x032 Saturation       : Char
   +0x033 Priority         : Char
   +0x034 ApcState         : _KAPC_STATE
   +0x04c ContextSwitches  : Uint4B
   +0x050 IdleSwapBlock    : UChar
   +0x051 Spare0           : [3] UChar
   +0x054 WaitStatus       : Int4B
   +0x058 WaitIrql         : UChar
   +0x059 WaitMode         : Char
   +0x05a WaitNext         : UChar
   +0x05b WaitReason       : UChar

   +0x05c WaitBlockList    : Ptr32 _KWAIT_BLOCK
   +0x060 WaitListEntry    : _LIST_ENTRY
   +0x060 SwapListEntry    : _SINGLE_LIST_ENTRY
   +0x068 WaitTime         : Uint4B
   +0x06c BasePriority     : Char
   +0x06d DecrementCount   : UChar
   +0x06e PriorityDecrement : Char
   +0x06f Quantum          : Char
   +0x070 WaitBlock        : [4] _KWAIT_BLOCK
   +0x0d0 LegoData         : Ptr32 Void
   +0x0d4 KernelApcDisable : Uint4B
   +0x0d8 UserAffinity     : Uint4B
   +0x0dc SystemAffinityActive : UChar
   +0x0dd PowerState       : UChar
   +0x0de NpxIrql          : UChar
   +0x0df InitialNode      : UChar
   +0x0e0 ServiceTable     : Ptr32 Void
   +0x0e4 Queue            : Ptr32 _KQUEUE
   +0x0e8 ApcQueueLock     : Uint4B
   +0x0f0 Timer            : _KTIMER
   +0x118 QueueListEntry   : _LIST_ENTRY
   +0x120 SoftAffinity     : Uint4B
   +0x124 Affinity         : Uint4B
   +0x128 Preempted        : UChar
   +0x129 ProcessReadyQueue : UChar
   +0x12a KernelStackResident : UChar
   +0x12b NextProcessor    : UChar
   +0x12c CallbackStack    : Ptr32 Void
   +0x130 Win32Thread      : Ptr32 Void
   +0x134 TrapFrame        : Ptr32 _KTRAP_FRAME
   +0x138 ApcStatePointer  : [2] Ptr32 _KAPC_STATE
   +0x140 PreviousMode     : Char
   +0x141 EnableStackSwap  : UChar
   +0x142 LargeStack       : UChar
   +0x143 ResourceIndex    : UChar
   +0x144 KernelTime       : Uint4B
   +0x148 UserTime         : Uint4B
   +0x14c SavedApcState    : _KAPC_STATE
   +0x164 Alertable        : UChar
   +0x165 ApcStateIndex    : UChar
   +0x166 ApcQueueable     : UChar
   +0x167 AutoAlignment    : UChar
   +0x168 StackBase        : Ptr32 Void
   +0x16c SuspendApc       : _KAPC
   +0x19c SuspendSemaphore : _KSEMAPHORE
   +0x1b0 ThreadListEntry  : _LIST_ENTRY
   +0x1b8 FreezeCount      : Char
   +0x1b9 SuspendCount     : Char
   +0x1ba IdealProcessor   : UChar
   +0x1bb DisableBoost     : UChar
*/

typedef struct _NT_TIB32 {
    uint32_t ExceptionList; // PEXCEPTION_REGISTRATION_RECORD
    uint32_t StackBase;     // PVOID
    uint32_t StackLimit;    // PVOID
    uint32_t SubSystemTib;  // PVOID
    union {
        uint32_t FiberData; // PVOID
        uint32_t Version;   // ULONG
    };
    uint32_t ArbitraryUserPointer;
    uint32_t Self; // PNT_TIB
} __attribute__((packed)) NT_TIB32;

struct DESCRIPTOR32 {
    uint16_t Pad;
    uint16_t Limit;
    uint32_t Base;
} __attribute__((packed));

struct KSPECIAL_REGISTERS32 {
    uint32_t Cr0;
    uint32_t Cr2;
    uint32_t Cr3;
    uint32_t Cr4;
    uint32_t KernelDr0;
    uint32_t KernelDr1;
    uint32_t KernelDr2;
    uint32_t KernelDr3;
    uint32_t KernelDr6;
    uint32_t KernelDr7;
    DESCRIPTOR32 Gdtr;
    DESCRIPTOR32 Idtr;
    uint16_t Tr;
    uint16_t Ldtr;
    uint32_t Reserved[6];
} __attribute__((packed));

typedef enum _INTERFACE_TYPE {
    InterfaceTypeUndefined = -1,
    Internal,
    Isa,
    Eisa,
    MicroChannel,
    TurboChannel,
    PCIBus,
    VMEBus,
    NuBus,
    PCMCIABus,
    CBus,
    MPIBus,
    MPSABus,
    ProcessorInternal,
    InternalPowerBus,
    PNPISABus,
    PNPBus,
    MaximumInterfaceType
} INTERFACE_TYPE,
    *PINTERFACE_TYPE;

struct FLOATING_SAVE_AREA {
    uint32_t ControlWord;
    uint32_t StatusWord;
    uint32_t TagWord;
    uint32_t ErrorOffset;
    uint32_t ErrorSelector;
    uint32_t DataOffset;
    uint32_t DataSelector;
    uint8_t RegisterArea[80];
    uint32_t Cr0NpxState;
} __attribute__((packed));

struct CONTEXT32 {
    uint32_t ContextFlags;
    uint32_t Dr0;
    uint32_t Dr1;
    uint32_t Dr2;
    uint32_t Dr3;
    uint32_t Dr6;
    uint32_t Dr7;
    FLOATING_SAVE_AREA FloatSave;
    uint32_t SegGs;
    uint32_t SegFs;
    uint32_t SegEs;
    uint32_t SegDs;
    uint32_t Edi;
    uint32_t Esi;
    uint32_t Ebx;
    uint32_t Edx;
    uint32_t Ecx;
    uint32_t Eax;
    uint32_t Ebp;
    uint32_t Eip;
    uint32_t SegCs;
    uint32_t EFlags;
    uint32_t Esp;
    uint32_t SegSs;
    uint8_t ExtendedRegisters[512];
} __attribute__((packed));

struct M128A {
    uint64_t Low;
    int64_t High;
} __attribute__((aligned(16)));
;

//
// Format of data for (F)XSAVE/(F)XRSTOR instruction
//

struct XSAVE_FORMAT64 {
    uint16_t ControlWord;
    uint16_t StatusWord;
    uint8_t TagWord;
    uint8_t Reserved1;
    uint16_t ErrorOpcode;
    uint32_t ErrorOffset;
    uint16_t ErrorSelector;
    uint16_t Reserved2;
    uint32_t DataOffset;
    uint16_t DataSelector;
    uint16_t Reserved3;
    uint32_t MxCsr;
    uint32_t MxCsr_Mask;
    M128A FloatRegisters[8];

#if 1 // defined(_WIN64)

    M128A XmmRegisters[16];
    uint8_t Reserved4[96];

#else

    M128A XmmRegisters[8];
    uint8_t Reserved4[220];

    //
    // Cr0NpxState is not a part of XSAVE/XRSTOR format. The OS is relying on
    // a fact that neither (FX)SAVE nor (F)XSTOR uses this area.
    //

    uint32_t Cr0NpxState;

#endif

} __attribute__((aligned(16)));

struct CONTEXT64 {

    //
    // Register parameter home addresses.
    //
    // N.B. These fields are for convience - they could be used to extend the
    //      context record in the future.
    //

    uint64_t P1Home;
    uint64_t P2Home;
    uint64_t P3Home;
    uint64_t P4Home;
    uint64_t P5Home;
    uint64_t P6Home;

    //
    // Control flags.
    //

    uint32_t ContextFlags;
    uint32_t MxCsr;

    //
    // Segment Registers and processor flags.
    //

    uint16_t SegCs;
    uint16_t SegDs;
    uint16_t SegEs;
    uint16_t SegFs;
    uint16_t SegGs;
    uint16_t SegSs;
    uint32_t EFlags;

    //
    // Debug registers
    //

    uint64_t Dr0;
    uint64_t Dr1;
    uint64_t Dr2;
    uint64_t Dr3;
    uint64_t Dr6;
    uint64_t Dr7;

    //
    // Integer registers.
    //

    uint64_t Rax;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rbx;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;

    //
    // Program counter.
    //

    uint64_t Rip;

    //
    // Floating point state.
    //

    union {
        XSAVE_FORMAT64 FltSave;
        struct {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    //
    // Vector registers.
    //

    M128A VectorRegister[26];
    uint64_t VectorControl;

    //
    // Special debug control registers.
    //

    uint64_t DebugControl;
    uint64_t LastBranchToRip;
    uint64_t LastBranchFromRip;
    uint64_t LastExceptionToRip;
    uint64_t LastExceptionFromRip;
} __attribute__((aligned(16)));

#define CONTEXT_i386 0x00010000
#define CONTEXT_i486 0x00010000

#define CONTEXT_CONTROL            (CONTEXT_i386 | 0x00000001L)
#define CONTEXT_INTEGER            (CONTEXT_i386 | 0x00000002L)
#define CONTEXT_SEGMENTS           (CONTEXT_i386 | 0x00000004L)
#define CONTEXT_FLOATING_POINT     (CONTEXT_i386 | 0x00000008L)
#define CONTEXT_DEBUG_REGISTERS    (CONTEXT_i386 | 0x00000010L)
#define CONTEXT_EXTENDED_REGISTERS (CONTEXT_i386 | 0x00000020L)

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)

#define EXCEPTION_MAXIMUM_PARAMETERS 15

#define EXCEPTION_NONCONTINUABLE  0x0001
#define EXCEPTION_UNWINDING       0x0002
#define EXCEPTION_EXIT_UNWIND     0x0004
#define EXCEPTION_STACK_INVALID   0x0008
#define EXCEPTION_NESTED_CALL     0x0010
#define EXCEPTION_TARGET_UNWIND   0x0020
#define EXCEPTION_COLLIDED_UNWIND 0x0040
#define EXCEPTION_UNWIND          0x0066

#define STATUS_BREAKPOINT 0x80000003

struct EXCEPTION_RECORD32 {
    uint32_t ExceptionCode;
    uint32_t ExceptionFlags;
    uint32_t ExceptionRecord;  // struct _EXCEPTION_RECORD
    uint32_t ExceptionAddress; // PVOID
    uint32_t NumberParameters;
    uint32_t ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} __attribute__((packed));

struct EXCEPTION_RECORD64 {
    uint32_t ExceptionCode;
    uint32_t ExceptionFlags;
    uint64_t ExceptionRecord;  // struct _EXCEPTION_RECORD
    uint64_t ExceptionAddress; // PVOID
    uint32_t NumberParameters;
    uint32_t __unusedAlignment;
    uint64_t ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} __attribute__((packed));

struct KPROCESSOR_STATE32 {
    CONTEXT32 ContextFrame;
    KSPECIAL_REGISTERS32 SpecialRegisters;
} __attribute__((packed));

static const uint32_t KPRCB32_DPC_STACK_OFFSET = 0x868;
struct KPRCB32 {
    uint16_t MinorVersion;
    uint16_t MajorVersion;
    uint32_t CurrentThread;
    uint32_t NextThread;
    uint32_t IdleThread;
    uint8_t Number;
    uint8_t WakeIdle;
    uint16_t BuildType;
    uint32_t SetMember;
    uint32_t RestartBlock;

    KPROCESSOR_STATE32 ProcessorState;

} __attribute__((packed));

struct MDL32 {
    uint32_t Next; // struct _MDL *
    CSHORT Size;
    CSHORT MdlFlags;
    uint32_t Process; // struct _EPROCESS *
    uint32_t MappedSystemVa;
    uint32_t StartVa;
    ULONG ByteCount;
    ULONG ByteOffset;
};

static const uint32_t MDL_MAPPED_TO_SYSTEM_VA = 0x0001;
static const uint32_t MDL_PAGES_LOCKED = 0x0002;
static const uint32_t MDL_SOURCE_IS_NONPAGED_POOL = 0x0004;
static const uint32_t MDL_ALLOCATED_FIXED_SIZE = 0x0008;
static const uint32_t MDL_PARTIAL = 0x0010;
static const uint32_t MDL_PARTIAL_HAS_BEEN_MAPPED = 0x0020;
static const uint32_t MDL_IO_PAGE_READ = 0x0040;
static const uint32_t MDL_WRITE_OPERATION = 0x0080;
static const uint32_t MDL_PARENT_MAPPED_SYSTEM_VA = 0x0100;
static const uint32_t MDL_FREE_EXTRA_PTES = 0x0200;
static const uint32_t MDL_IO_SPACE = 0x0800;
static const uint32_t MDL_NETWORK_HEADER = 0x1000;
static const uint32_t MDL_MAPPING_CAN_FAIL = 0x2000;
static const uint32_t MDL_ALLOCATED_MUST_SUCCEED = 0x4000;

static const uint32_t MDL_MAPPING_FLAGS = (MDL_MAPPED_TO_SYSTEM_VA | MDL_PAGES_LOCKED | MDL_SOURCE_IS_NONPAGED_POOL |
                                           MDL_PARTIAL_HAS_BEEN_MAPPED | MDL_PARENT_MAPPED_SYSTEM_VA |
                                           //       MDL_SYSTEM_VA               |
                                           MDL_IO_SPACE);

static const uint32_t METHOD_BUFFERED = 0;
static const uint32_t METHOD_IN_DIRECT = 1;
static const uint32_t METHOD_OUT_DIRECT = 2;
static const uint32_t METHOD_NEITHER = 3;

enum BUS_DATA_TYPE {
    ConfigurationSpaceUndefined = -1,
    Cmos,
    EisaConfiguration,
    Pos,
    CbusConfiguration,
    PCIConfiguration,
    VMEConfiguration,
    NuBusConfiguration,
    PCMCIAConfiguration,
    MPIConfiguration,
    MPSAConfiguration,
    PNPISAConfiguration,
    MaximumBusDataType
};

//
// HAL Bus Handler
//
struct BUS_HANDLER32 {
    uint32_t Version;
    INTERFACE_TYPE InterfaceType;
    BUS_DATA_TYPE ConfigurationType;
    uint32_t BusNumber;
    uint32_t DeviceObject;  // PDEVICE_OBJECT
    uint32_t ParentHandler; // struct _BUS_HANDLER *
    uint32_t BusData;       // PVOID
    uint32_t DeviceControlExtensionSize;
    // PSUPPORTED_RANGES BusAddresses;
    uint32_t Reserved[4];
#if 0
    pGetSetBusData GetBusData;
    pGetSetBusData SetBusData;
    pAdjustResourceList AdjustResourceList;
    pAssignSlotResources AssignSlotResources;
    pGetInterruptVector GetInterruptVector;
    pTranslateBusAddress TranslateBusAddress;
#endif
};

struct LUID {
    uint32_t LowPart;
    uint32_t HighPart;
};

typedef uint32_t PSID;

struct SE_EXPORTS {
    LUID SeCreateTokenPrivilege;
    LUID SeAssignPrimaryTokenPrivilege;
    LUID SeLockMemoryPrivilege;
    LUID SeIncreaseQuotaPrivilege;
    LUID SeUnsolicitedInputPrivilege;
    LUID SeTcbPrivilege;
    LUID SeSecurityPrivilege;
    LUID SeTakeOwnershipPrivilege;
    LUID SeLoadDriverPrivilege;
    LUID SeCreatePagefilePrivilege;
    LUID SeIncreaseBasePriorityPrivilege;
    LUID SeSystemProfilePrivilege;
    LUID SeSystemtimePrivilege;
    LUID SeProfileSingleProcessPrivilege;
    LUID SeCreatePermanentPrivilege;
    LUID SeBackupPrivilege;
    LUID SeRestorePrivilege;
    LUID SeShutdownPrivilege;
    LUID SeDebugPrivilege;
    LUID SeAuditPrivilege;
    LUID SeSystemEnvironmentPrivilege;
    LUID SeChangeNotifyPrivilege;
    LUID SeRemoteShutdownPrivilege;
    PSID SeNullSid;
    PSID SeWorldSid;
    PSID SeLocalSid;
    PSID SeCreatorOwnerSid;
    PSID SeCreatorGroupSid;
    PSID SeNtAuthoritySid;
    PSID SeDialupSid;
    PSID SeNetworkSid;
    PSID SeBatchSid;
    PSID SeInteractiveSid;
    PSID SeLocalSystemSid;
    PSID SeAliasAdminsSid;
    PSID SeAliasUsersSid;
    PSID SeAliasGuestsSid;
    PSID SeAliasPowerUsersSid;
    PSID SeAliasAccountOpsSid;
    PSID SeAliasSystemOpsSid;
    PSID SeAliasPrintOpsSid;
    PSID SeAliasBackupOpsSid;
    PSID SeAuthenticatedUsersSid;
    PSID SeRestrictedSid;
    PSID SeAnonymousLogonSid;
    LUID SeUndockPrivilege;
    LUID SeSyncAgentPrivilege;
    LUID SeEnableDelegationPrivilege;
    PSID SeLocalServiceSid;
    PSID SeNetworkServiceSid;
    LUID SeManageVolumePrivilege;
    LUID SeImpersonatePrivilege;
    LUID SeCreateGlobalPrivilege;
    LUID SeTrustedCredManAccessPrivilege;
    LUID SeRelabelPrivilege;
    LUID SeIncreaseWorkingSetPrivilege;
    LUID SeTimeZonePrivilege;
    LUID SeCreateSymbolicLinkPrivilege;
    PSID SeIUserSid;
    PSID SeUntrustedMandatorySid;
    PSID SeLowMandatorySid;
    PSID SeMediumMandatorySid;
    PSID SeHighMandatorySid;
    PSID SeSystemMandatorySid;
    PSID SeOwnerRightsSid;
    PSID SeAllAppPackagesSid;
};

typedef ULONG DEVICE_TYPE;

typedef uint32_t KSPIN_LOCK;

struct KDEVICE_QUEUE32 {
    CSHORT Type;
    CSHORT Size;
    LIST_ENTRY32 DeviceListHead;
    KSPIN_LOCK Lock;

#if defined(_AMD64_)

    union {
        BOOLEAN Busy;
        struct {
            LONG64 Reserved : 8;
            LONG64 Hint : 56;
        };
    };

#else

    BOOLEAN Busy;

#endif
};

struct KDEVICE_QUEUE_ENTRY32 {
    LIST_ENTRY32 DeviceListEntry;
    uint32_t SortKey;
    BOOLEAN Inserted;
};

struct WAIT_CONTEXT_BLOCK32 {
    KDEVICE_QUEUE_ENTRY32 WaitQueueEntry;
    uint32_t DeviceRoutine; // PDRIVER_CONTROL
    uint32_t DeviceContext; // PVOID
    ULONG NumberOfMapRegisters;
    uint32_t DeviceObject;      // PVOID
    uint32_t CurrentIrp;        // PVOID
    uint32_t BufferChainingDpc; // PKDPC
};

struct KDPC32 {
    UCHAR Type;
    UCHAR Importance;
    volatile USHORT Number;
    LIST_ENTRY32 DpcListEntry;
    uint32_t DeferredRoutine; // PKDEFERRED_ROUTINE
    uint32_t DeferredContext; // PVOID
    uint32_t SystemArgument1; // PVOID
    uint32_t SystemArgument2; // PVOID
    uint32_t DpcData;         // PVOID
};

#define TIMER_EXPIRED_INDEX_BITS   6
#define TIMER_PROCESSOR_INDEX_BITS 5

struct DISPATCHER_HEADER32 {
    union {
        struct {
            UCHAR Type; // All (accessible via KOBJECT_TYPE)

            union {
                union { // Timer
                    UCHAR TimerControlFlags;
                    struct {
                        UCHAR Absolute : 1;
                        UCHAR Coalescable : 1;
                        UCHAR KeepShifting : 1;          // Periodic timer
                        UCHAR EncodedTolerableDelay : 5; // Periodic timer
                    } DUMMYSTRUCTNAME;
                } DUMMYUNIONNAME;

                UCHAR Abandoned;    // Queue
                BOOLEAN Signalling; // Gate/Events
            } DUMMYUNIONNAME;

            union {
                union {
                    UCHAR ThreadControlFlags; // Thread
                    struct {
                        UCHAR CpuThrottled : 1;
                        UCHAR CycleProfiling : 1;
                        UCHAR CounterProfiling : 1;
                        UCHAR Reserved : 5;
                    } DUMMYSTRUCTNAME;
                } DUMMYUNIONNAME;
                UCHAR Hand; // Timer
                UCHAR Size; // All other objects
            } DUMMYUNIONNAME2;

            union {
                union { // Timer
                    UCHAR TimerMiscFlags;
                    struct {

#if !defined(_X86_)

                        UCHAR Index : TIMER_EXPIRED_INDEX_BITS;

#else

                        UCHAR Index : 1;
                        UCHAR Processor : TIMER_PROCESSOR_INDEX_BITS;

#endif

                        UCHAR Inserted : 1;
                        volatile UCHAR Expired : 1;
                    } DUMMYSTRUCTNAME;
                } DUMMYUNIONNAME1;
                union { // Thread
                    BOOLEAN DebugActive;
                    struct {
                        BOOLEAN ActiveDR7 : 1;
                        BOOLEAN Instrumented : 1;
                        BOOLEAN Reserved2 : 4;
                        BOOLEAN UmsScheduled : 1;
                        BOOLEAN UmsPrimary : 1;
                    } DUMMYSTRUCTNAME;
                } DUMMYUNIONNAME2;
                BOOLEAN DpcActive; // Mutant
            } DUMMYUNIONNAME3;
        } DUMMYSTRUCTNAME;

        volatile LONG Lock; // Interlocked
    } DUMMYUNIONNAME;

    LONG SignalState;          // Object lock
    LIST_ENTRY32 WaitListHead; // Object lock
};

struct KEVENT32 {
    DISPATCHER_HEADER32 Header;
};

struct DEVICE_OBJECT32 {
    CSHORT Type;
    USHORT Size;
    LONG ReferenceCount;
    uint32_t DriverObject;   // struct _DRIVER_OBJECT *
    uint32_t NextDevice;     // struct _DEVICE_OBJECT *
    uint32_t AttachedDevice; // struct _DEVICE_OBJECT *
    uint32_t CurrentIrp;     // struct _IRP *
    uint32_t Timer;          // PIO_TIMER
    ULONG Flags;
    ULONG Characteristics;
    uint32_t Vpb;             //__volatile PVPB
    uint32_t DeviceExtension; // PVOID
    DEVICE_TYPE DeviceType;
    CCHAR StackSize;
    union {
        LIST_ENTRY32 ListEntry;
        WAIT_CONTEXT_BLOCK32 Wcb;
    } Queue;
    ULONG AlignmentRequirement;
    KDEVICE_QUEUE32 DeviceQueue;
    KDPC32 Dpc;
    ULONG ActiveThreadCount;
    uint32_t SecurityDescriptor; // PSECURITY_DESCRIPTOR
    KEVENT32 DeviceLock;
    USHORT SectorSize;
    USHORT Spare1;
    uint32_t DeviceObjectExtension; // struct _DEVOBJ_EXTENSION  *
    uint32_t Reserved;              // PVOID
};

struct FILE_OBJECT32 {
    CSHORT Type;
    CSHORT Size;
    uint32_t DeviceObject;         // PDEVICE_OBJECT
    uint32_t Vpb;                  // PVPB
    uint32_t FsContext;            // PVOID
    uint32_t FsContext2;           // PVOID
    uint32_t SectionObjectPointer; // PSECTION_OBJECT_POINTERS
    uint32_t PrivateCacheMap;      // PVOID
    NTSTATUS FinalStatus;
    uint32_t RelatedFileObject; // struct _FILE_OBJECT *
    BOOLEAN LockOperation;
    BOOLEAN DeletePending;
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    ULONG Flags;
    UNICODE_STRING32 FileName;
    uint64_t CurrentByteOffset; // LARGE_INTEGER
    __volatile ULONG Waiters;
    __volatile ULONG Busy;
    uint32_t LastLock; // PVOID
    KEVENT32 Lock;
    KEVENT32 Event;
    uint32_t CompletionContext; //__volatile PIO_COMPLETION_CONTEXT
    KSPIN_LOCK IrpListLock;
    LIST_ENTRY32 IrpList;
    uint32_t FileObjectExtension; //__volatile PVOID
};

struct KTIMER32 {
    DISPATCHER_HEADER32 Header;
    uint64_t DueTime; // ULARGE_INTEGER
    LIST_ENTRY32 TimerListEntry;
    uint32_t Dpc; // struct _KDPC  *
    LONG Period;
};

typedef uint64_t LARGE_INTEGER;

struct ETHREAD32 {
    uint8_t Tcb[0x1c0];
    LARGE_INTEGER CreateTime;
    union {
        LARGE_INTEGER ExitTime;
        LIST_ENTRY32 KeyedWaitChain;
    };
    union {
        LONG ExitStatus;
        uint32_t OfsChain;
    };

    LIST_ENTRY32 PostBlockList;

    union {
        uint32_t TerminationPort; // PTERMINATION_PORT
        uint32_t ReaperLink;      // PETHREAD
        uint32_t KeyedWaitValue;  // PETHREAD
    };

    ULONG ActiveTimerListLock;
    LIST_ENTRY32 ActiveTimerListHead;
    uint32_t Cid[2]; // CLIENT_ID

    union {
        uint8_t KeyedWaitSemaphore[0x14]; // KSEMAPHORE
        uint8_t AlpcWaitSemaphore[0x14];  // KSEMAPHORE
    };

    uint32_t LpcReplyMessage;

    uint32_t ImpersonationInfo;
    LIST_ENTRY32 IrpList;
    ULONG TopLevelIrp;
    uint32_t DeviceToVerify; // PDEVICE_OBJECT
    uint32_t ThreadsProcess; // PEPROCESS

    uint32_t StartAddress;
    uint32_t Win32StartAddress;
    LIST_ENTRY32 ThreadListEntry;
    //...
} __attribute__((packed));

/*
+0x000 Tcb              : _KTHREAD

   +0x1c0 CreateTime       : _LARGE_INTEGER
   +0x1c0 NestedFaultCount : Pos 0, 2 Bits
   +0x1c0 ApcNeeded        : Pos 2, 1 Bit

   +0x1c8 ExitTime         : _LARGE_INTEGER
   +0x1c8 LpcReplyChain    : _LIST_ENTRY
   +0x1c8 KeyedWaitChain   : _LIST_ENTRY

   +0x1d0 ExitStatus       : Int4B
   +0x1d0 OfsChain         : Ptr32 Void

   +0x1d4 PostBlockList    : _LIST_ENTRY

   +0x1dc TerminationPort  : Ptr32 _TERMINATION_PORT
   +0x1dc ReaperLink       : Ptr32 _ETHREAD
   +0x1dc KeyedWaitValue   : Ptr32 Void

   +0x1e0 ActiveTimerListLock : Uint4B
   +0x1e4 ActiveTimerListHead : _LIST_ENTRY
   +0x1ec Cid              : _CLIENT_ID

   +0x1f4 LpcReplySemaphore : _KSEMAPHORE
   +0x1f4 KeyedWaitSemaphore : _KSEMAPHORE

   +0x208 LpcReplyMessage  : Ptr32 Void
   +0x208 LpcWaitingOnPort : Ptr32 Void

   +0x20c ImpersonationInfo : Ptr32 _PS_IMPERSONATION_INFORMATION
   +0x210 IrpList          : _LIST_ENTRY
   +0x218 TopLevelIrp      : Uint4B
   +0x21c DeviceToVerify   : Ptr32 _DEVICE_OBJECT
   +0x220 ThreadsProcess   : Ptr32 _EPROCESS
   +0x224 StartAddress     : Ptr32 Void
   +0x228 Win32StartAddress : Ptr32 Void
   +0x228 LpcReceivedMessageId : Uint4B
   +0x22c ThreadListEntry  : _LIST_ENTRY

*/

static const uint32_t ETHREAD32_THREADLISTENTRY_OFFSET_XP = 0x22c;
static const uint32_t EPROCESS32_THREADLISTHEAD_OFFSET_XP = 0x190;

static const uint32_t ETHREAD32_SIZE = 0x234;

static const uint32_t STATUS_SUCCESS = 0;
static const uint32_t STATUS_PENDING = 0x00000103;
static const uint32_t STATUS_BUFFER_TOO_SMALL = 0xC0000023;
static const uint32_t STATUS_UNKNOWN_REVISION = 0xC0000058;
static const uint32_t STATUS_INVALID_SECURITY_DESCR = 0xC0000079;
static const uint32_t STATUS_BAD_DESCRIPTOR_FORMAT = 0xC00000E7;

typedef uint32_t PACL32;
typedef uint32_t PSID32;
typedef uint16_t SECURITY_DESCRIPTOR_CONTROL;
typedef uint32_t PDEVICE_OBJECT32;
typedef uint8_t KPROCESSOR_MODE;
typedef uint8_t KIRQL;

typedef ULONG SECURITY_INFORMATION;
typedef uint32_t LCID;

#define POINTER_ALIGNMENT

enum DEVICE_RELATION_TYPE {
    BusRelations,
    EjectionRelations,
    PowerRelations,
    RemovalRelations,
    TargetDeviceRelation,
    SingleBusRelations
};

enum BUS_QUERY_ID_TYPE {
    BusQueryDeviceID = 0,
    BusQueryHardwareIDs = 1,
    BusQueryCompatibleIDs = 2,
    BusQueryInstanceID = 3,
    BusQueryDeviceSerialNumber = 4
};

enum DEVICE_TEXT_TYPE { DeviceTextDescription = 0, DeviceTextLocationInformation = 1 };

enum DEVICE_USAGE_NOTIFICATION_TYPE {
    DeviceUsageTypeUndefined,
    DeviceUsageTypePaging,
    DeviceUsageTypeHibernation,
    DeviceUsageTypeDumpFile
};

enum SYSTEM_POWER_STATE {
    PowerSystemUnspecified = 0,
    PowerSystemWorking = 1,
    PowerSystemSleeping1 = 2,
    PowerSystemSleeping2 = 3,
    PowerSystemSleeping3 = 4,
    PowerSystemHibernate = 5,
    PowerSystemShutdown = 6,
    PowerSystemMaximum = 7
};

enum POWER_STATE_TYPE { SystemPowerState = 0, DevicePowerState };

enum DEVICE_POWER_STATE {
    PowerDeviceUnspecified = 0,
    PowerDeviceD0,
    PowerDeviceD1,
    PowerDeviceD2,
    PowerDeviceD3,
    PowerDeviceMaximum
};

enum POWER_ACTION {
    PowerActionNone = 0,
    PowerActionReserved,
    PowerActionSleep,
    PowerActionHibernate,
    PowerActionShutdown,
    PowerActionShutdownReset,
    PowerActionShutdownOff,
    PowerActionWarmEject
};

union POWER_STATE {
    SYSTEM_POWER_STATE SystemState;
    DEVICE_POWER_STATE DeviceState;
};

enum FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,   // 2
    FileBothDirectoryInformation,   // 3
    FileBasicInformation,           // 4
    FileStandardInformation,        // 5
    FileInternalInformation,        // 6
    FileEaInformation,              // 7
    FileAccessInformation,          // 8
    FileNameInformation,            // 9
    FileRenameInformation,          // 10
    FileLinkInformation,            // 11
    FileNamesInformation,           // 12
    FileDispositionInformation,     // 13
    FilePositionInformation,        // 14
    FileFullEaInformation,          // 15
    FileModeInformation,            // 16
    FileAlignmentInformation,       // 17
    FileAllInformation,             // 18
    FileAllocationInformation,      // 19
    FileEndOfFileInformation,       // 20
    FileAlternateNameInformation,   // 21
    FileStreamInformation,          // 22
    FilePipeInformation,            // 23
    FilePipeLocalInformation,       // 24
    FilePipeRemoteInformation,      // 25
    FileMailslotQueryInformation,   // 26
    FileMailslotSetInformation,     // 27
    FileCompressionInformation,     // 28
    FileObjectIdInformation,        // 29
    FileCompletionInformation,      // 30
    FileMoveClusterInformation,     // 31
    FileQuotaInformation,           // 32
    FileReparsePointInformation,    // 33
    FileNetworkOpenInformation,     // 34
    FileAttributeTagInformation,    // 35
    FileTrackingInformation,        // 36
    FileIdBothDirectoryInformation, // 37
    FileIdFullDirectoryInformation, // 38
    FileValidDataLengthInformation, // 39
    FileShortNameInformation,       // 40
    FileMaximumInformation
};

enum FS_INFORMATION_CLASS {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,      // 2
    FileFsSizeInformation,       // 3
    FileFsDeviceInformation,     // 4
    FileFsAttributeInformation,  // 5
    FileFsControlInformation,    // 6
    FileFsFullSizeInformation,   // 7
    FileFsObjectIdInformation,   // 8
    FileFsDriverPathInformation, // 9
    FileFsMaximumInformation
};

struct SECURITY_DESCRIPTOR32 {
    uint8_t Revision;
    uint8_t Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    PSID32 Owner;
    PSID32 Group;
    PACL32 Sacl;
    PACL32 Dacl;
} __attribute__((packed));

typedef struct _FILE_OBJECT *PFILE_OBJECT;

struct IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;

    union {
        struct {
            uint32_t SecurityContext;
            ULONG Options;
            USHORT POINTER_ALIGNMENT FileAttributes;
            USHORT ShareAccess;
            ULONG POINTER_ALIGNMENT EaLength;
        } Create;

        struct {
            ULONG Length;
            ULONG POINTER_ALIGNMENT Key;
            uint64_t ByteOffset;
        } Read;

        struct {
            ULONG Length;
            ULONG POINTER_ALIGNMENT Key;
            uint64_t ByteOffset;
        } Write;

        struct {
            ULONG Length;
            FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
        } QueryFile;

        struct {
            ULONG Length;
            FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
            uint32_t FileObject;
            union {
                struct {
                    BOOLEAN ReplaceIfExists;
                    BOOLEAN AdvanceOnly;
                };
                ULONG ClusterCount;
                HANDLE DeleteHandle;
            };
        } SetFile;

        struct {
            ULONG Length;
            FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;
        } QueryVolume;

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT IoControlCode;
            uint32_t Type3InputBuffer;
        } DeviceIoControl;

        struct {
            SECURITY_INFORMATION SecurityInformation;
            ULONG POINTER_ALIGNMENT Length;
        } QuerySecurity;

        struct {
            SECURITY_INFORMATION SecurityInformation;
            uint32_t SecurityDescriptor;
        } SetSecurity;

        struct {
            uint32_t Vpb;
            uint32_t DeviceObject;
        } MountVolume;

        struct {
            uint32_t Vpb;
            uint32_t DeviceObject;
        } VerifyVolume;

        struct {
            uint32_t Srb;
        } Scsi;

        struct {
            DEVICE_RELATION_TYPE Type;
        } QueryDeviceRelations;

        struct {
            uint32_t InterfaceType;
            USHORT Size;
            USHORT Version;
            uint32_t Interface;
            uint32_t InterfaceSpecificData;
        } QueryInterface;

        struct {
            uint32_t Capabilities;
        } DeviceCapabilities;

        struct {
            uint32_t IoResourceRequirementList;
        } FilterResourceRequirements;

        struct {
            ULONG WhichSpace;
            uint32_t Buffer;
            ULONG Offset;
            ULONG POINTER_ALIGNMENT Length;
        } ReadWriteConfig;

        struct {
            BOOLEAN Lock;
        } SetLock;

        struct {
            BUS_QUERY_ID_TYPE IdType;
        } QueryId;

        struct {
            DEVICE_TEXT_TYPE DeviceTextType;
            LCID POINTER_ALIGNMENT LocaleId;
        } QueryDeviceText;

        struct {
            BOOLEAN InPath;
            BOOLEAN Reserved[3];
            DEVICE_USAGE_NOTIFICATION_TYPE POINTER_ALIGNMENT Type;
        } UsageNotification;

        struct {
            SYSTEM_POWER_STATE PowerState;
        } WaitWake;

        struct {
            uint32_t PowerSequence;
        } PowerSequence;

        struct {
            ULONG SystemContext;
            POWER_STATE_TYPE POINTER_ALIGNMENT Type;
            POWER_STATE POINTER_ALIGNMENT State;
            POWER_ACTION POINTER_ALIGNMENT ShutdownType;
        } Power;

        struct {
            uint32_t AllocatedResources;
            uint32_t AllocatedResourcesTranslated;
        } StartDevice;

        struct {
            uint32_t ProviderId;
            uint32_t DataPath;
            ULONG BufferSize;
            uint32_t Buffer;
        } WMI;

        struct {
            uint32_t Argument1;
            uint32_t Argument2;
            uint32_t Argument3;
            uint32_t Argument4;
        } Others;

    } Parameters;

    uint32_t DeviceObject;

    uint32_t FileObject; // FILE_OBJECT

    uint32_t CompletionRoutine;

    uint32_t Context;

} __attribute__((packed));

struct KAPC32 {
    uint16_t Type;
    uint16_t Size;
    uint32_t Spare0;
    uint32_t Thread;
    LIST_ENTRY32 ApcListEntry;
    uint32_t KernelRoutine;
    uint32_t RundownRoutine;
    uint32_t NormalRoutine;
    uint32_t NormalContext;

    uint32_t SystemArgument1;
    uint32_t SystemArgument2;
    uint8_t ApcStateIndex;
    KPROCESSOR_MODE ApcMode;
    BOOLEAN Inserted;
};

struct IO_STATUS_BLOCK32 {
    union {
        uint32_t Status;
        uint32_t Pointer;
    };

    uint32_t Information;
};

struct IRP {
    uint16_t Type;
    uint16_t Size;
    uint32_t MdlAddress;
    uint32_t Flags;

    union {
        uint32_t MasterIrp;
        int32_t IrpCount;
        uint32_t SystemBuffer;
    } AssociatedIrp;

    LIST_ENTRY32 ThreadListEntry;
    IO_STATUS_BLOCK32 IoStatus;
    int8_t RequestorMode;
    uint8_t PendingReturned;
    int8_t StackCount;
    int8_t CurrentLocation;
    uint8_t Cancel;
    uint8_t CancelIrql;
    int8_t ApcEnvironment;
    uint8_t AllocationFlags;

    uint32_t UserIosb;
    uint32_t UserEvent;
    union {
        struct {
            uint32_t UserApcRoutine;
            uint32_t UserApcContext;
        } AsynchronousParameters;
        uint64_t AllocationSize;
    } Overlay;

    uint32_t CancelRoutine;
    uint32_t UserBuffer;

    union {
        struct {
            union {
                KDEVICE_QUEUE_ENTRY32 DeviceQueueEntry;
                struct {
                    uint32_t DriverContext[4];
                };
            };

            uint32_t Thread;
            uint32_t AuxiliaryBuffer;

            struct {
                LIST_ENTRY32 ListEntry;
                union {
                    uint32_t CurrentStackLocation; // struct IO_STACK_LOCATION *
                    uint32_t PacketType;
                };
            };
            uint32_t OriginalFileObject;
        } Overlay;

        KAPC32 Apc;
        uint32_t CompletionKey;

    } Tail;
};

static const uint32_t IRP_MJ_CREATE = 0x00;
static const uint32_t IRP_MJ_CREATE_NAMED_PIPE = 0x01;
static const uint32_t IRP_MJ_CLOSE = 0x02;
static const uint32_t IRP_MJ_READ = 0x03;
static const uint32_t IRP_MJ_WRITE = 0x04;
static const uint32_t IRP_MJ_QUERY_INFORMATION = 0x05;
static const uint32_t IRP_MJ_SET_INFORMATION = 0x06;
static const uint32_t IRP_MJ_QUERY_EA = 0x07;
static const uint32_t IRP_MJ_SET_EA = 0x08;
static const uint32_t IRP_MJ_FLUSH_BUFFERS = 0x09;
static const uint32_t IRP_MJ_QUERY_VOLUME_INFORMATION = 0x0a;
static const uint32_t IRP_MJ_SET_VOLUME_INFORMATION = 0x0b;
static const uint32_t IRP_MJ_DIRECTORY_CONTROL = 0x0c;
static const uint32_t IRP_MJ_FILE_SYSTEM_CONTROL = 0x0d;
static const uint32_t IRP_MJ_DEVICE_CONTROL = 0x0e;
static const uint32_t IRP_MJ_INTERNAL_DEVICE_CONTROL = 0x0f;
static const uint32_t IRP_MJ_SCSI = 0x0f;
static const uint32_t IRP_MJ_SHUTDOWN = 0x10;
static const uint32_t IRP_MJ_LOCK_CONTROL = 0x11;
static const uint32_t IRP_MJ_CLEANUP = 0x12;
static const uint32_t IRP_MJ_CREATE_MAILSLOT = 0x13;
static const uint32_t IRP_MJ_QUERY_SECURITY = 0x14;
static const uint32_t IRP_MJ_SET_SECURITY = 0x15;
static const uint32_t IRP_MJ_POWER = 0x16;
static const uint32_t IRP_MJ_SYSTEM_CONTROL = 0x17;
static const uint32_t IRP_MJ_DEVICE_CHANGE = 0x18;
static const uint32_t IRP_MJ_QUERY_QUOTA = 0x19;
static const uint32_t IRP_MJ_SET_QUOTA = 0x1a;
static const uint32_t IRP_MJ_PNP = 0x1b;
static const uint32_t IRP_MJ_PNP_POWER = 0x1b;
static const uint32_t IRP_MJ_MAXIMUM_FUNCTION = 0x1b;

typedef uint32_t MM_PROTECTION_MASK;

static const unsigned MM_ZERO_ACCESS = 0;
static const unsigned MM_READONLY = 1;
static const unsigned MM_EXECUTE = 2;
static const unsigned MM_EXECUTE_READ = 3;
static const unsigned MM_READWRITE = 4;
static const unsigned MM_WRITECOPY = 5;
static const unsigned MM_EXECUTE_READWRITE = 6;
static const unsigned MM_EXECUTE_WRITECOPY = 7;

struct MMVADFLAGS32_XP {
    unsigned CommitCharge : 0x13;
    unsigned PhysicalMapping : 0x1;
    unsigned ImageMap : 0x1;
    unsigned UserPhysicalPages : 0x1;
    unsigned NoChange : 0x1;
    unsigned WriteWatch : 0x1;
    MM_PROTECTION_MASK Protection : 0x5;
    unsigned LargePages : 0x1;
    unsigned MemCommit : 0x1;
    unsigned PrivateMemory : 0x1;
} __attribute__((packed));

struct MMVAD32_XP {
    uint32_t StartingVpn;
    uint32_t EndingVpn;
    uint32_t Parent;
    uint32_t Left;
    uint32_t Right;
    MMVADFLAGS32_XP VadFlags;
};

struct KTRAP_FRAME32 {
    ULONG DbgEbp;
    ULONG DbgEip;
    ULONG DbgArgMark;
    ULONG DbgArgPointer;
    WORD TempSegCs;
    UCHAR Logging;
    UCHAR Reserved;
    ULONG TempEsp;
    ULONG Dr0;
    ULONG Dr1;
    ULONG Dr2;
    ULONG Dr3;
    ULONG Dr6;
    ULONG Dr7;
    ULONG SegGs;
    ULONG SegEs;
    ULONG SegDs;
    ULONG Edx;
    ULONG Ecx;
    ULONG Eax;
    ULONG PreviousPreviousMode;
    uint32_t ExceptionList;
    ULONG SegFs;
    ULONG Edi;
    ULONG Esi;
    ULONG Ebx;
    ULONG Ebp;
    ULONG ErrCode;
    ULONG Eip;
    ULONG SegCs;
    ULONG EFlags;
    ULONG HardwareEsp;
    ULONG HardwareSegSs;
    ULONG V86Es;
    ULONG V86Ds;
    ULONG V86Fs;
    ULONG V86Gs;
} __attribute__((packed));

struct KTRAP_FRAME64 {

    //
    // Home address for the parameter registers.
    //

    ULONG64 P1Home;
    ULONG64 P2Home;
    ULONG64 P3Home;
    ULONG64 P4Home;
    ULONG64 P5;

    //
    // Previous processor mode (system services only) and previous IRQL
    // (interrupts only).
    //

    KPROCESSOR_MODE PreviousMode;
    KIRQL PreviousIrql;

    //
    // Page fault load/store indicator.
    //

    UCHAR FaultIndicator;

    //
    // Exception active indicator.
    //
    //    0 - interrupt frame.
    //    1 - exception frame.
    //    2 - service frame.
    //

    UCHAR ExceptionActive;

    //
    // Floating point state.
    //

    ULONG MxCsr;

    //
    //  Volatile registers.
    //
    // N.B. These registers are only saved on exceptions and interrupts. They
    //      are not saved for system calls.
    //

    ULONG64 Rax;
    ULONG64 Rcx;
    ULONG64 Rdx;
    ULONG64 R8;
    ULONG64 R9;
    ULONG64 R10;
    ULONG64 R11;

    //
    // Gsbase is only used if the previous mode was kernel.
    //
    // GsSwap is only used if the previous mode was user.
    //

    union {
        ULONG64 GsBase;
        ULONG64 GsSwap;
    };

    //
    // Volatile floating registers.
    //
    // N.B. These registers are only saved on exceptions and interrupts. They
    //      are not saved for system calls.
    //

    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;

    //
    // First parameter, page fault address, context record address if user APC
    // bypass, or time stamp value.
    //

    union {
        ULONG64 FaultAddress;
        ULONG64 ContextRecord;
        ULONG64 TimeStampCKCL;
    };

    //
    //  Debug registers.
    //

    ULONG64 Dr0;
    ULONG64 Dr1;
    ULONG64 Dr2;
    ULONG64 Dr3;
    ULONG64 Dr6;
    ULONG64 Dr7;

    //
    // Special debug registers.
    //
    // N.B. Either AMD64 or EM64T information is stored in the following
    // locations.
    //

    union {
        struct {
            ULONG64 DebugControl;
            ULONG64 LastBranchToRip;
            ULONG64 LastBranchFromRip;
            ULONG64 LastExceptionToRip;
            ULONG64 LastExceptionFromRip;
        };

        struct {
            ULONG64 LastBranchControl;
            ULONG LastBranchMSR;
        };
    };

    //
    //  Segment registers
    //

    USHORT SegDs;
    USHORT SegEs;
    USHORT SegFs;
    USHORT SegGs;

    //
    // Previous trap frame address.
    //

    ULONG64 TrapFrame;

    //
    // Saved nonvolatile registers RBX, RDI and RSI. These registers are only
    // saved in system service trap frames.
    //

    ULONG64 Rbx;
    ULONG64 Rdi;
    ULONG64 Rsi;

    //
    // Saved nonvolatile register RBP. This register is used as a frame
    // pointer during trap processing and is saved in all trap frames.
    //

    ULONG64 Rbp;

    //
    // Information pushed by hardware.
    //
    // N.B. The error code is not always pushed by hardware. For those cases
    //      where it is not pushed by hardware a dummy error code is allocated
    //      on the stack.
    //

    union {
        ULONG64 ErrorCode;
        ULONG64 ExceptionFrame;
        ULONG64 TimeStampKlog;
    };

    ULONG64 Rip;
    USHORT SegCs;
    UCHAR Fill0;
    UCHAR Logging;
    USHORT Fill1[2];
    ULONG EFlags;
    ULONG Fill2;
    ULONG64 Rsp;
    USHORT SegSs;
    USHORT Fill3;

    //
    // Copy of the global patch cycle at the time of the fault. Filled in by the
    // invalid opcode and general protection fault routines.
    //

    LONG CodePatchCycle;
};
} // namespace windows
} // namespace vmi

#endif
