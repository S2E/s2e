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

#include <iostream>
#include <vmi/WinKernDumpFile.h>

namespace vmi {
namespace windows {

WinKernDumpFile::~WinKernDumpFile() {
}

bool WinKernDumpFile::initializePointerSize() {
    // Determine 32-bits/64-bits
    uint32_t signature[2];

    if (!m_file->readb(signature, sizeof(signature), 0)) {
        return false;
    }

    if (signature[0] != DUMP_HDR_SIGNATURE) {
        return false;
    }

    switch (signature[1]) {
        case DUMP_HDR_DUMPSIGNATURE:
            m_pointerSize = sizeof(uint32_t);
            break;
        case DUMP_HDR_DUMPSIGNATURE64:
            m_pointerSize = sizeof(uint64_t);
            break;
        default:
            return false;
    }

    return true;
}

bool WinKernDumpFile::open(bool writable) {
    if (writable) {
        return false;
    }

    if (!initializePointerSize()) {
        return false;
    }

    bool result;

    if (m_pointerSize == sizeof(uint64_t)) {
        result = m_file->readb(&Header64, sizeof(Header64), 0);
    } else {
        result = m_file->readb(&Header32, sizeof(Header32), 0);
    }

    return result;
}

ssize_t WinKernDumpFile::read(void *buffer, size_t nbyte, off64_t offset) {
    return -1;
}

ssize_t WinKernDumpFile::write(const void *buffer, size_t nbyte, off64_t offset) {
    return -1;
}

int WinKernDumpFile::stat(struct stat *buf) {
    return -1;
}

const char *WinKernDumpFile::getName() const {
    return m_file->getName();
}
} // namespace windows
} // namespace vmi
