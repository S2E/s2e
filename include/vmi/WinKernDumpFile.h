///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <vmi/WindowsCrashDumpGenerator.h>
#include "FileProvider.h"

#ifndef VMI_WINKERN_DUMPFILE

#define VMI_WINKERN_DUMPFILE

namespace vmi {
namespace windows {

class WinKernDumpFile : public FileProvider {
private:
    FileProvider *m_file;
    unsigned m_pointerSize;

    DUMP_HEADER64 Header64;
    DUMP_HEADER32 Header32;

    bool initializePointerSize();

public:
    WinKernDumpFile(FileProvider *file) : m_file(file) {
    }
    virtual ~WinKernDumpFile();

    virtual bool open(bool writable);
    virtual ssize_t read(void *buffer, size_t nbyte, off64_t offset);
    virtual ssize_t write(const void *buffer, size_t nbyte, off64_t offset);
    virtual int stat(struct stat *buf);
    virtual const char *getName() const;

    unsigned getPointerSize() const {
        return m_pointerSize;
    }

    bool getHeader32(DUMP_HEADER32 &Header) const {
        if (m_pointerSize != sizeof(uint32_t)) {
            return false;
        }
        Header = Header32;
        return true;
    }

    bool getHeader64(DUMP_HEADER64 &Header) const {
        if (m_pointerSize != sizeof(uint64_t)) {
            return false;
        }
        Header = Header64;
        return true;
    }
};
}
}

#endif
