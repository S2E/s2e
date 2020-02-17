///
/// Copyright (C) 2019, Cyberhaven
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

#ifndef S2E_KVM_TRACE_H

#define S2E_KVM_TRACE_H

#include <cpu/kvm.h>
#include <inttypes.h>

#include "FileDescriptorManager.h"
#include "syscalls.h"

namespace s2e {
namespace kvm {

class KVMTrace : public IFile {
private:
    int m_kvm_fd;

    KVMTrace(int fd) : m_kvm_fd(fd) {
    }

public:
    static IFilePtr create();

    virtual ~KVMTrace() {
    }
    virtual int sys_ioctl(int fd, int request, uint64_t arg1);
};

class KVMTraceVM : public IFile {
private:
    int m_kvm_vm_fd;

    KVMTraceVM(int vm_fd) : m_kvm_vm_fd(vm_fd) {
    }

public:
    static IFilePtr create(int vm_fd);
    virtual ~KVMTraceVM() {
    }
    virtual int sys_ioctl(int fd, int request, uint64_t arg1);
};

class KVMTraceVCPU : public IFile {
private:
    int m_kvm_vcpu_fd;

    KVMTraceVCPU(int vcpu_fd) : m_kvm_vcpu_fd(vcpu_fd) {
    }

public:
    static IFilePtr create(int vcpu_fd);
    virtual ~KVMTraceVCPU() {
    }
    virtual int sys_ioctl(int fd, int request, uint64_t arg1);
    virtual void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
};
} // namespace kvm
} // namespace s2e

#endif
