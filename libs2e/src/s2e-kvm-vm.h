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

#ifndef S2E_KVM_VM_H

#define S2E_KVM_VM_H

#include <cpu/kvm.h>
#include <inttypes.h>

#include "FileDescriptorManager.h"
#include "s2e-kvm.h"

namespace s2e {
namespace kvm {

class VCPU;

class VM : public IFile {
private:
    std::shared_ptr<S2EKVM> m_kvm;
    std::shared_ptr<VCPU> m_cpu;

    VM(std::shared_ptr<S2EKVM> &kvm) : m_kvm(kvm) {
    }

    int enableCapability(kvm_enable_cap *cap);

    int createVirtualCPU();

    int setTSSAddress(uint64_t tss_addr);

    int setUserMemoryRegion(kvm_userspace_memory_region *region);

    ///
    /// \brief memoryReadWrite intercepts all dma read/writes from the kvm client.
    ///
    /// This is important in order to keep the cpu code cache consistent as well
    /// as to keep track of dirty page.
    ///
    /// In multi-path mode, this ensures that dma reads/writes go to the right state
    /// in addition to keeping track of dirty pages.
    ///
    /// \param vm_fd the vm descriptor
    /// \param mem the memory descriptor
    /// \return
    ///
    int memoryReadWrite(kvm_mem_rw *mem);

    int registerFixedRegion(kvm_fixed_region *region);

    ///
    /// \brief getDirtyLog returns a bitmap of dirty pages
    /// for the given memory buffer.
    ///
    /// This is usually used for graphics memory by kvm clients.
    ///
    /// \param vm_fd the virtual machine fd
    /// \param log the bitmap structure
    /// \return
    ///
    int getDirtyLog(kvm_dirty_log *log);

    int setIdentityMapAddress(uint64_t addr);

    int setClock(kvm_clock_data *clock);
    int getClock(kvm_clock_data *clock);

    int ioEventFD(kvm_ioeventfd *event);

    int diskReadWrite(kvm_disk_rw *d);
    int deviceSnapshot(kvm_dev_snapshot *s);
    int setClockScalePointer(unsigned *scale);

public:
    virtual ~VM() {
    }

    static std::shared_ptr<VM> create(std::shared_ptr<S2EKVM> &kvm);

    void sendCpuExitSignal();
    virtual int sys_ioctl(int fd, int request, uint64_t arg1);
};
} // namespace kvm
} // namespace s2e

#endif
