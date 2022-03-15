///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
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

#ifndef VMI_PE_DEFS_H
#define VMI_PE_DEFS_H

#include <inttypes.h>

namespace vmi {
namespace windows {

static const uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;    // MZ
static const uint32_t IMAGE_NT_SIGNATURE = 0x00004550; // PE00

// Directory Entries
static const unsigned IMAGE_DIRECTORY_ENTRY_EXPORT = 0;    // Export Directory
static const unsigned IMAGE_DIRECTORY_ENTRY_IMPORT = 1;    // Import Directory
static const unsigned IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;  // Resource Directory
static const unsigned IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3; // Exception Directory
static const unsigned IMAGE_DIRECTORY_ENTRY_SECURITY = 4;  // Security Directory
static const unsigned IMAGE_DIRECTORY_ENTRY_BASERELOC = 5; // Base Relocation Table
static const unsigned IMAGE_DIRECTORY_ENTRY_DEBUG = 6;     // Debug Directory
// IMAGE_DIRECTORY_ENTRY_COPYRIGHT 7 // (X86 usage)
static const unsigned IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7;    // Architecture Specific Data
static const unsigned IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;       // RVA of GP
static const unsigned IMAGE_DIRECTORY_ENTRY_TLS = 9;             // TLS Directory
static const unsigned IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;    // Load Configuration Directory
static const unsigned IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;   // Bound Import Directory in headers
static const unsigned IMAGE_DIRECTORY_ENTRY_IAT = 12;            // Import Address Table
static const unsigned IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;   // Delay Load Import Descriptors
static const unsigned IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14; // COM Runtime descriptor

static const uint32_t IMAGE_ORDINAL_FLAG = 0x80000000;

struct IMAGE_DOS_HEADER { // DOS .EXE header
    uint16_t e_magic;     // Magic number
    uint16_t e_cblp;      // Bytes on last page of file
    uint16_t e_cp;        // Pages in file
    uint16_t e_crlc;      // Relocations
    uint16_t e_cparhdr;   // Size of header in paragraphs
    uint16_t e_minalloc;  // Minimum extra paragraphs needed
    uint16_t e_maxalloc;  // Maximum extra paragraphs needed
    uint16_t e_ss;        // Initial (relative) SS value
    uint16_t e_sp;        // Initial SP value
    uint16_t e_csum;      // Checksum
    uint16_t e_ip;        // Initial IP value
    uint16_t e_cs;        // Initial (relative) CS value
    uint16_t e_lfarlc;    // File address of relocation table
    uint16_t e_ovno;      // Overlay number
    uint16_t e_res[4];    // Reserved uint16_ts
    uint16_t e_oemid;     // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;   // OEM information; e_oemid specific
    uint16_t e_res2[10];  // Reserved uint16_ts
    int32_t e_lfanew;     // File address of new exe header
} __attribute__((packed));

struct IMAGE_FILE_HEADER { // 20 bytes
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} __attribute__((packed));

static const unsigned IMAGE_FILE_MACHINE_I386 = 0x014c;

static const unsigned IMAGE_FILE_MACHINE_AMD64 = 0x8664;

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
} __attribute__((packed));

static const unsigned IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

struct IMAGE_OPTIONAL_HEADER32 { // 96 + ... bytes
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint; //+16 bytes
    uint32_t BaseOfCode;
    uint32_t BaseOfData;

    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} __attribute__((packed));

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint; //+16 bytes
    uint32_t BaseOfCode;

    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_NT_HEADERS32 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} __attribute__((packed));

struct IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} __attribute__((packed));

struct IMAGE_THUNK_DATA32 {
    union {
        uint32_t ForwarderString; // PBYTE
        uint32_t Function;        // Puint32_t
        uint32_t Ordinal;
        uint32_t AddressOfData; // IMAGE_IMPORT_BY_NAME *
    } u1;
} __attribute__((packed));

struct IMAGE_THUNK_DATA64 {
    union {
        uint64_t ForwarderString;
        uint64_t Function;
        uint64_t Ordinal;
        uint64_t AddressOfData;
    } u1;
};

struct IMAGE_IMPORT_BY_NAME {
    uint16_t Hint;
    uint8_t Name[1];
} __attribute__((packed));

struct IMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32_t Characteristics;    // 0 for terminating null import descriptor
        uint32_t OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    uint32_t TimeDateStamp; // 0 if not bound,
                            // -1 if bound, and real date\time stamp
                            // in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                            // O.W. date/time stamp of DLL bound to (Old BIND)

    uint32_t ForwarderChain; // -1 if no forwarders
    uint32_t Name;
    uint32_t FirstThunk; // RVA to IAT (if bound this IAT has actual addresses)
} __attribute__((packed));

struct IMAGE_BASE_RELOCATION32 {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
    // USHORT TypeOffset[1];
} __attribute__((packed));

static const unsigned IMAGE_SIZEOF_SHORT_NAME = 8;

struct IMAGE_SECTION_HEADER {
    uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} __attribute__((packed));

static const uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;
static const uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
static const uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;

static const uint32_t IMAGE_SCN_CNT_CODE = 0x20;
static const uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40;

static const unsigned IMAGE_SIZEOF_SECTION_HEADER32 = 40;

//
// DLL support.
//

//
// Export Format
//

struct IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;    // RVA from base of image
    uint32_t AddressOfNames;        // RVA from base of image
    uint32_t AddressOfNameOrdinals; // RVA from base of image
} __attribute__((packed));

#ifndef IMAGE_ORDINAL_FLAG
#define IMAGE_ORDINAL_FLAG 0x80000000
#endif

//
// Based relocation format.
//

struct IMAGE_BASE_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
    //  uint16_t   TypeOffset[1];
} __attribute__((packed));

//
// Based relocation types.
//

static const uint32_t IMAGE_REL_BASED_ABSOLUTE = 0;
static const uint32_t IMAGE_REL_BASED_HIGH = 1;
static const uint32_t IMAGE_REL_BASED_LOW = 2;
static const uint32_t IMAGE_REL_BASED_HIGHLOW = 3;
static const uint32_t IMAGE_REL_BASED_HIGHADJ = 4;
static const uint32_t IMAGE_REL_BASED_MACHINE_SPECIFIC_5 = 5;
static const uint32_t IMAGE_REL_BASED_RESERVED = 6;
static const uint32_t IMAGE_REL_BASED_MACHINE_SPECIFIC_7 = 7;
static const uint32_t IMAGE_REL_BASED_MACHINE_SPECIFIC_8 = 8;
static const uint32_t IMAGE_REL_BASED_MACHINE_SPECIFIC_9 = 9;
static const uint32_t IMAGE_REL_BASED_DIR64 = 10;

struct RUNTIME_FUNCTION {
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t UnwindData;
} __attribute__((packed));

union UNWIND_CODE {
    struct {
        uint8_t CodeOffset;
        uint8_t UnwindOp : 4;
        uint8_t OpInfo : 4;
    };
    uint16_t FrameOffset;
} __attribute__((packed));

static const uint32_t UNW_FLAG_NHANDLER = 0x0;
static const uint32_t UNW_FLAG_EHANDLER = 0x1;
static const uint32_t UNW_FLAG_UHANDLER = 0x2;
static const uint32_t UNW_FLAG_CHAININFO = 0x4;

struct UNWIND_INFO {
    uint8_t Version : 3;
    uint8_t Flags : 5;
    uint8_t SizeOfProlog;
    uint8_t CountOfCodes;
    uint8_t FrameRegister : 4;
    uint8_t FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    union {
        //
        // If (Flags & UNW_FLAG_EHANDLER)
        //
        uint32_t ExceptionHandler;
        //
        // Else if (Flags & UNW_FLAG_CHAININFO)
        //
        uint32_t FunctionEntry;
    };
    //
    // If (Flags & UNW_FLAG_EHANDLER)
    //
    uint32_t ExceptionData[];
} __attribute__((packed));

struct SCOPE_TABLE {
    uint32_t Count;
    struct {
        uint32_t BeginAddress;
        uint32_t EndAddress;
        uint32_t HandlerAddress;
        uint32_t JumpTarget;
    } ScopeRecord[1];
} __attribute__((packed));

#define MAGIC_VC  0x19930520 // up to VC6
#define MAGIC_VC7 0x19930521 // VC7.x(2002-2003)
#define MAGIC_VC8 0x19930522 // VC8 (2005)

struct EhRef {
    uint32_t Id;
    uint32_t Cnt1;
    uint32_t Tbl1;
    uint32_t Cnt2;
    uint32_t Tbl2;
    uint32_t Cnt3;
    uint32_t Tbl3;
} __attribute__((packed));

struct UnwindHandler {
    uint32_t Mode;
    uint32_t Entry;
} __attribute__((packed));

struct ExceptionTypeHandler {
    uint32_t Entry;
    uint32_t Mode;
} __attribute__((packed));
} // namespace windows
} // namespace vmi

#endif
