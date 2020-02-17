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

#ifndef S2E_KVM_H

#define S2E_KVM_H

#include <cpu/i386/cpuid.h>
#include <cpu/kvm.h>
#include <inttypes.h>

#include "FileDescriptorManager.h"
#include "syscalls.h"

namespace s2e {
namespace kvm {

struct stats_t {
    uint64_t mmio_reads;
    uint64_t mmio_writes;
    uint64_t io_reads;
    uint64_t io_writes;

    uint64_t kvm_runs;
    uint64_t cpu_exit;
};

extern struct stats_t g_stats;

class VM;

class S2EKVM : public IFile {
private:
    static const char *s_cpuModel;
    static const bool s_is64;

    pthread_t m_timerThread;
    bool m_exiting = false;
    volatile bool m_timerExited = false;
    cpuid_t m_cpuid;

    std::shared_ptr<VM> m_vm;

#ifdef CONFIG_SYMBEX
    static std::string getBitcodeLibrary(const std::string &dir);
#endif

    static void *timerCb(void *param);
    void init(void);
    void initLogLevel(void);

    S2EKVM() = default;

    static void cleanup();

    void sendCpuExitSignal();

    int getApiVersion(void);
    int createVM();
    int getMSRIndexList(kvm_msr_list *list);
    int getSupportedCPUID(kvm_cpuid2 *cpuid);

public:
    virtual ~S2EKVM() {
    }

    static IFilePtr create();
    static int getVCPUMemoryMapSize(void);

    virtual int sys_ioctl(int fd, int request, uint64_t arg1);

    int checkExtension(int capability);
    int initTimerThread(void);

    bool exiting() const {
        return m_exiting;
    }

    void setExiting() {
        m_exiting = true;
    }

    const cpuid_t &getCpuid() const {
        return m_cpuid;
    }
};
} // namespace kvm
} // namespace s2e

#endif
