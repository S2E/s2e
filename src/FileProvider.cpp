///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <vmi/FileProvider.h>

#include <llvm/Support/MemoryBuffer.h>

namespace vmi {

namespace {

class BufferedFSFP : public FileSystemFileProvider {
    // Use buffered files to avoid too many syscalls (most reads are a few bytes
    // large).
    FILE *m_fp;

    bool open(bool writable) {
        const char *mode = writable ? "wb" : "rb";
        m_fp = fopen(m_file.c_str(), mode);
        return m_fp != nullptr;
    }

public:
    static BufferedFSFP *get(const std::string &filename, bool writable) {
        BufferedFSFP *fp = new BufferedFSFP(filename);
        if (!fp->open(writable)) {
            delete fp;
            fp = nullptr;
        }
        return fp;
    }

    BufferedFSFP(const std::string &file) : FileSystemFileProvider(file), m_fp(nullptr) {
    }

    virtual ~BufferedFSFP() {
        if (m_fp) {
            fclose(m_fp);
        }
    }

    virtual ssize_t read(void *buffer, size_t nbyte, off64_t offset) {
        if (nbyte == 0) {
            return nbyte;
        }

        if (this->seek(offset) < 0) {
            return -1;
        }

        if (::fread(buffer, nbyte, 1, m_fp) != 1) {
            return -1;
        }

        return nbyte;
    }

    virtual ssize_t write(const void *buffer, size_t nbyte, off64_t offset) {
        if (nbyte == 0) {
            return nbyte;
        }

        if (this->seek(offset) < 0) {
            return -1;
        }

        return write(buffer, nbyte);
    }

    virtual ssize_t write(const void *buffer, size_t nbyte) {
        assert(m_fp);

        if (nbyte == 0) {
            return nbyte;
        }

        if (::fwrite(buffer, nbyte, 1, m_fp) != 1) {
            return -1;
        }

        return nbyte;
    }

    virtual off64_t seek(off64_t offset) {
        assert(m_fp);

        if (::fseek(m_fp, offset, SEEK_SET) < 0) {
            return -1;
        }

        return offset;
    }

    virtual off64_t tell() {
        assert(m_fp);
        return ::ftell(m_fp);
    }

    virtual int stat(struct stat *buf) {
        assert(m_fp);
        return ::fstat(fileno(m_fp), buf);
    }
};

///
/// \brief The MappedFSFP class uses memory mapping instead
/// of I/O to access files. This eliminates all read/seek syscalls
/// that may slow down access on some configurations (e.g., on
/// network drives).
///
/// It does not support write access yet.
///
class MappedFSFP : public FileSystemFileProvider {
    std::unique_ptr<llvm::MemoryBuffer> m_buffer;
    size_t m_offset;

    bool open(bool writable) {
        auto buffer = llvm::MemoryBuffer::getFile(m_file, -1, false);
        if (buffer.getError()) {
            return false;
        }
        m_buffer = std::move(buffer.get());
        return true;
    }

    MappedFSFP(const std::string &file) : FileSystemFileProvider(file), m_buffer(), m_offset(0) {
    }

public:
    static MappedFSFP *get(const std::string &filename, bool writable) {
        assert(!writable);
        MappedFSFP *ret = new MappedFSFP(filename);
        if (ret->open(writable)) {
            return ret;
        }
        delete ret;
        return nullptr;
    }

    virtual ssize_t read(void *buffer, size_t nbyte, off64_t offset) {
        size_t sz = m_buffer->getBufferSize();
        if ((size_t) offset >= sz) {
            return 0;
        }

        ssize_t to_read = offset + nbyte < sz ? nbyte : sz - offset;
        memcpy(buffer, m_buffer->getBufferStart() + offset, to_read);
        m_offset = offset + to_read;
        return to_read;
    }

    virtual ssize_t write(const void *buffer, size_t nbyte, off64_t offset) {
        return -1;
    }

    virtual ssize_t write(const void *buffer, size_t nbyte) {
        return -1;
    }

    virtual off64_t seek(off64_t offset) {
        if ((size_t) offset >= m_buffer->getBufferSize()) {
            return -1;
        }
        m_offset = offset;
        return offset;
    }

    virtual off64_t tell() {
        return m_offset;
    }

    virtual int stat(struct stat *buf) {
        memset(buf, 0, sizeof(*buf));
        // XXX: fix me
        buf->st_size = m_buffer->getBufferSize();
        return 0;
    }
};
}

/************************************************************/

FileSystemFileProvider *FileSystemFileProvider::get(const std::string &filename, bool writable) {
    // We use mapped files for the read-only case
    if (!writable) {
        return MappedFSFP::get(filename, writable);
    } else {
        return BufferedFSFP::get(filename, writable);
    }
}

FileSystemFileProvider::FileSystemFileProvider(const std::string &file) : m_file(file) {
}

FileSystemFileProvider::~FileSystemFileProvider() {
}

const char *FileSystemFileProvider::getName() const {
    return m_file.c_str();
}

/************************************************************/

GuestMemoryFileProvider *GuestMemoryFileProvider::get(void *opaque, GuestMemoryFileProvider::ReadMemoryCb readCb,
                                                      GuestMemoryFileProvider::WriteMemoryCb writeCb,
                                                      const std::string &name) {
    return new GuestMemoryFileProvider(opaque, readCb, writeCb, name);
}

GuestMemoryFileProvider::GuestMemoryFileProvider(void *opaque, ReadMemoryCb readCb, WriteMemoryCb writeCb,
                                                 const std::string &name)
    : m_read(readCb), m_write(writeCb), m_opaque(opaque), m_name(name) {
}

GuestMemoryFileProvider::~GuestMemoryFileProvider() {
}

bool GuestMemoryFileProvider::open(bool writable) {
    if (writable) {
        if (!m_write) {
            return false;
        }
    } else {
        m_write = nullptr;
    }
    return true;
}

ssize_t GuestMemoryFileProvider::read(void *buffer, size_t nbyte, off64_t offset) {
    if (m_read(m_opaque, offset, buffer, nbyte)) {
        return nbyte;
    }
    return -1;
}

ssize_t GuestMemoryFileProvider::write(const void *buffer, size_t nbyte, off64_t offset) {
    if (m_write && m_write(m_opaque, offset, buffer, nbyte)) {
        return nbyte;
    }
    return -1;
}

int GuestMemoryFileProvider::stat(struct stat *buf) {
    memset(buf, 0, sizeof(*buf));
    // XXX: fix me
    buf->st_size = -1;
    return 0;
}

const char *GuestMemoryFileProvider::getName() const {
    return m_name.c_str();
}
}
