///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
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

#ifndef VMI_FILEPROVIDER_H

#define VMI_FILEPROVIDER_H

#include <inttypes.h>
#include <memory>
#include <stdio.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

namespace vmi {

class FileProvider {
public:
    virtual ~FileProvider() {
    }

    // XXX: use bool as return values, more intuitive.
    virtual ssize_t read(void *buffer, size_t nbyte, off64_t offset) = 0;
    virtual ssize_t write(const void *buffer, size_t nbyte, off64_t offset) = 0;
    virtual ssize_t write(const void *buffer, size_t nbyte) {
        return -1;
    }
    virtual off64_t seek(off64_t offset) {
        return -1;
    }
    virtual off64_t tell() {
        return -1;
    }
    virtual int stat(struct stat *buf) = 0;
    virtual const char *getName() const = 0;

    bool readb(void *buffer, size_t nbyte, off64_t offset) {
        ssize_t ret = read(buffer, nbyte, offset);
        if (ret < 0) {
            return false;
        }

        return (size_t) ret == nbyte;
    }

    bool writeb(const void *buffer, size_t nbyte, off64_t offset) {
        ssize_t ret = write(buffer, nbyte, offset);
        if (ret < 0) {
            return false;
        }

        return (size_t) ret == nbyte;
    }

    bool writeb(const void *buffer, size_t nbyte) {
        ssize_t ret = write(buffer, nbyte);
        if (ret < 0) {
            return false;
        }

        return (size_t) ret == nbyte;
    }

    /** Read a generic string from memory */
    template <typename T> bool readGenericString(uint64_t address, std::string &s, unsigned maxLen) {
        s = "";
        bool ret = false;
        T c;

        do {
            c = 0;
            ret = readb(&c, sizeof(c), address);
            maxLen--;
            address += sizeof(T);

            if (c) {
                s = s + (char) c;
            }

        } while (c && (maxLen > 0));

        return ret;
    }

    /** Read an ASCIIZ string */
    bool readString(uint64_t address, std::string &s, unsigned maxLen = 256) {
        return readGenericString<uint8_t>(address, s, maxLen);
    }

    /** Read a unicode string */
    bool readUnicodeString(uint64_t address, std::string &s, unsigned maxLen = 256) {
        return readGenericString<uint16_t>(address, s, maxLen);
    }
};

class FileSystemFileProvider : public FileProvider {
protected:
    std::string m_file;

    FileSystemFileProvider(const std::string &file);

public:
    static std::shared_ptr<FileSystemFileProvider> get(const std::string &filename, bool writable);

    virtual ~FileSystemFileProvider();

    virtual const char *getName() const;
};

class GuestMemoryFileProvider : public FileProvider {
public:
    typedef bool (*ReadMemoryCb)(void *opaque, uint64_t address, void *buffer, unsigned size);
    typedef bool (*WriteMemoryCb)(void *opaque, uint64_t address, const void *buffer, unsigned size);

private:
    ReadMemoryCb m_read;
    WriteMemoryCb m_write;
    void *m_opaque;
    std::string m_name;

    bool open(bool writable);

    GuestMemoryFileProvider(void *opaque, ReadMemoryCb readCb, WriteMemoryCb writeCb, const std::string &name);

public:
    static std::shared_ptr<GuestMemoryFileProvider> get(void *opaque, ReadMemoryCb readCb, WriteMemoryCb writeCb,
                                                        const std::string &name);

    virtual ~GuestMemoryFileProvider();

    virtual ssize_t read(void *buffer, size_t nbyte, off64_t offset);
    virtual ssize_t write(const void *buffer, size_t nbyte, off64_t offset);
    virtual int stat(struct stat *buf);
    virtual const char *getName() const;
};
} // namespace vmi

#endif
