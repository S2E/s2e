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

#include <vmi/WindowsCrashDumpGenerator.h>
#include "FileProvider.h"

#ifndef VMI_WINKERN_DUMPFILE

#define VMI_WINKERN_DUMPFILE

namespace vmi {
namespace windows {

class WinKernDumpFile : public FileProvider {
private:
    std::shared_ptr<FileProvider> m_file;
    unsigned m_pointerSize;

    DUMP_HEADER64 Header64;
    DUMP_HEADER32 Header32;

    bool initializePointerSize();

public:
    WinKernDumpFile(std::shared_ptr<FileProvider> file) : m_file(file) {
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
} // namespace windows
} // namespace vmi

#endif
