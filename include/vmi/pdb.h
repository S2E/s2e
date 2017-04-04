///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef VMI_PDB_DEFS_H
#define VMI_PDB_DEFS_H

#include <inttypes.h>

namespace vmi {
namespace windows {

// 32-byte signature
#define MSF_SIGNATURE_700 "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0"

// MSF File Header
struct MSF_HDR {
    char szMagic[32];              // 0x00  Signature
    uint32_t dwPageSize;           // 0x20  Number of bytes in the pages (i.e. 0x400)
    uint32_t dwFpmPage;            // 0x24  FPM (free page map) page (i.e. 0x2)
    uint32_t dwPageCount;          // 0x28  Page count (i.e. 0x1973)
    uint32_t dwRootSize;           // 0x2c  Size of stream directory (in bytes; i.e. 0x6540)
    uint32_t dwReserved;           // 0x30  Always zero.
    uint32_t dwRootPointers[0x49]; // 0x34  Array of pointers to root pointers stream.
};

// The struct is followed by stream pointers.
struct MSF_ROOT {
    uint32_t dwStreamCount;
    uint32_t dwStreamSizes[];
};

#define ALIGN_DOWN(x, align) ((x) & ~(align - 1))
#define ALIGN_UP(x, align) (((x) & (align - 1)) ? ALIGN_DOWN(x, align) + align : (x))

#define PAGE(msf, x) (msf->MapB + msf->hdr->dwPageSize * (x))

// PDB Stream IDs
enum STREAM_IDS {
    PDB_STREAM_ROOT = 0,
    PDB_STREAM_PDB = 1,
    PDB_STREAM_TPI = 2,
    PDB_STREAM_DBI = 3,
    PDB_STREAM_FPO = 5,
    PDB_STREAM_IMPEXP = 16, // Revenged
};

// Followed by 2 bytes
struct PDB_IMPEXP_HDR {
    uint16_t Size;
    uint8_t NameOffset;
    uint8_t Unknown1;
    uint32_t Unknown2;
    uint32_t Unknown3;
    uint16_t Unknown4;
    uint8_t Name[]; // Pointed to by NameOffset
};
}
}

#include "FileProvider.h"

#include <vector>

namespace vmi {
class PDBReader {
private:
    FileProvider *m_fp;

    windows::MSF_HDR m_header;
    typedef std::vector<uint8_t> bytearray_t;

    typedef std::vector<uint32_t> DwordArray;
    typedef std::vector<DwordArray> StreamPointers;
    typedef std::vector<bytearray_t> Streams;

    DwordArray m_streamSizes;
    StreamPointers m_streamPointers;
    Streams m_streams;

    unsigned ConvertSizeToPageCount(unsigned size) {
        return ALIGN_UP(size, m_header.dwPageSize) / m_header.dwPageSize;
    }

    bool msfLoadPages(bytearray_t &result, const uint32_t *pagePointers, unsigned nPages);
    void computeStreamPointers(windows::MSF_ROOT *root);
    bool loadStream(bytearray_t &result, unsigned streamIndex);

public:
    PDBReader(FileProvider *fp);
    bool initialize();
    bool dumpImpExp();
};
}

#endif
