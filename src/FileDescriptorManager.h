///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_KVM_FDMGR_H

#define S2E_KVM_FDMGR_H

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <inttypes.h>
#include <memory>
#include <unordered_map>

namespace s2e {
namespace kvm {

class IFile {
public:
    virtual int sys_ioctl(int fd, int request, uint64_t arg1) {
        return -1;
    }

    virtual int close(int fd) {
        return -1;
    }

    virtual void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
        errno = ENOSYS;
        return MAP_FAILED;
    }

    // KVM interface does not support writes
    virtual ssize_t sys_write(int fd, const void *buf, size_t count) {
        printf("write %d count=%ld\n", fd, count);
        exit(-1);
        return -1;
    }

    virtual int sys_dup(int fd) {
        return -1;
    }
};

typedef std::shared_ptr<IFile> IFilePtr;

class FileDescriptorManager {
private:
    std::unordered_map<int, IFilePtr> m_map;

public:
    IFilePtr get(int fd) const {
        auto it = m_map.find(fd);
        if (it == m_map.end()) {
            return nullptr;
        }
        return (*it).second;
    }

    IFilePtr get(IFile *ptr) const {
        for (const auto &it : m_map) {
            if (it.second.get() == ptr) {
                return it.second;
            }
        }
        return nullptr;
    }

    int registerInterface(IFilePtr iface) {
        /* Reserve a dummy file descriptor */
        int fd = open("/dev/null", O_RDWR | O_CREAT | O_TRUNC, 0700);
        if (fd < 0) {
            return -1;
        }

        m_map[fd] = iface;
        return fd;
    }

    bool close(int fd) {
        auto ret = m_map.erase(fd) > 0;
        if (ret) {
            close(fd);
        }
        return ret;
    }
};

typedef std::shared_ptr<FileDescriptorManager> FileDescriptorManagerPtr;
}
}

#endif
