///
/// Copyright (C) 2015-2019, Cyberhaven
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

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <memory>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <fcntl.h>

#include <cpu/kvm.h>
#include "libs2e.h"
#include "s2e-kvm-trace.h"

namespace s2e {
namespace kvm {

static struct kvm_run *s_kvm_run;
static int s_kvm_vcpu_size;

static void trace_s2e_kvm_run(struct kvm_run *run, int ret) {
    printf("KVM_RUN EXIT ret=%#x reason=%#x apic_base=%llx cr8=%llx if_flag=%d req_int=%d rdy=%d\n", ret,
           run->exit_reason, run->apic_base, run->cr8, run->if_flag, run->request_interrupt_window,
           run->ready_for_interrupt_injection);
    switch (run->exit_reason) {
        case KVM_EXIT_IO: {
            printf("KVM_EXIT_IO dir=%d size=%d port=%#" PRIx16 " count=%d\n", run->io.direction, run->io.size,
                   run->io.port, run->io.count);
        } break;
        case KVM_EXIT_MMIO: {
            printf("KVM_EXIT_MMIO is_write=%d physaddr=%#llx len=%d\n", run->mmio.is_write, run->mmio.phys_addr,
                   run->mmio.len);
        } break;
    }
}

static void trace_s2e_kvm_set_user_memory_region(struct kvm_userspace_memory_region *region) {
    printf("%s %s slot=%d guest_phys=%llx size=%llx vaddr=%llx flags=%x\n", __FUNCTION__, "KVM_SET_USER_MEMORY_REGION",
           region->slot, region->guest_phys_addr, region->memory_size, region->userspace_addr, region->flags);
}

IFilePtr KVMTrace::create() {
    auto fd = g_original_open("/dev/kvm", O_RDWR, 0);
    if (fd < 0) {
        return nullptr;
    }

    return std::shared_ptr<KVMTrace>(new KVMTrace(fd));
}

int KVMTrace::sys_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;

    switch ((uint32_t) request) {
        case KVM_GET_API_VERSION:
            ret = g_original_ioctl(m_kvm_fd, request, arg1);
            printf("KVMTrace::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_API_VERSION", request,
                   arg1, ret);
            break;

        case KVM_CHECK_EXTENSION:
            switch (arg1) {
                case KVM_CAP_NR_MEMSLOTS: {
                    ret = g_original_ioctl(m_kvm_fd, request, arg1);
                } break;

                case KVM_CAP_MP_STATE:
                case KVM_CAP_EXT_CPUID:
                case KVM_CAP_SET_TSS_ADDR:
                case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
                case KVM_CAP_USER_MEMORY:
                case KVM_CAP_NR_VCPUS:
                case KVM_CAP_MAX_VCPUS:
                case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
                    // case KVM_CAP_READONLY_MEM:
                    ret = 1;
                    break;

                default:
                    // return s_original_ioctl(fd, request, arg1);
                    printf("Unsupported cap %#" PRIx64 "\n", arg1);
                    ret = -1;
                    break;
            }
            printf("KVMTrace::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_CHECK_EXTENSION", request,
                   arg1, ret);
            break;

        case KVM_CREATE_VM: {
            ret = g_original_ioctl(m_kvm_fd, request, arg1);
            if (ret < 0) {
                printf("Could not create vm fd (errno=%d %s)\n", errno, strerror(errno));
                exit(-1);
            }
            printf("KVMTrace::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_CREATE_VM", request, arg1,
                   ret);

            auto vm = KVMTraceVM::create(ret);
            ret = g_fdm->registerInterface(vm);

        } break;

        case KVM_GET_VCPU_MMAP_SIZE: {
            ret = g_original_ioctl(m_kvm_fd, request, arg1);
            printf("KVMTrace::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_VCPU_MMAP_SIZE",
                   request, arg1, ret);
            s_kvm_vcpu_size = ret;
        } break;

        case KVM_GET_MSR_INDEX_LIST: {
            ret = g_original_ioctl(m_kvm_fd, request, arg1);
            printf("KVMTrace::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_MSR_INDEX_LIST",
                   request, arg1, ret);
        } break;

        case KVM_GET_SUPPORTED_CPUID: {
            ret = g_original_ioctl(m_kvm_fd, request, arg1);
            printf("KVMTrace::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_SUPPORTED_CPUID",
                   request, arg1, ret);
        } break;

        default: {
            printf("KVMTrace::%s Unsupported request %x\n", __FUNCTION__, request);
            // return s_original_ioctl(fd, request, arg1);
            exit(-1);
        }
    }

    return ret;
}

IFilePtr KVMTraceVM::create(int vm_fd) {
    return std::shared_ptr<KVMTraceVM>(new KVMTraceVM(vm_fd));
}

int KVMTraceVM::sys_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;
    switch ((unsigned) request) {
        case KVM_SET_TSS_ADDR: {
            ret = g_original_ioctl(m_kvm_vm_fd, request, arg1);
            printf("KVMTraceVM::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_SET_TSS_ADDR", request,
                   arg1, ret);
        } break;

        case KVM_CREATE_VCPU: {
            ret = g_original_ioctl(m_kvm_vm_fd, request, arg1);
            printf("KVMTraceVM: created vcpu %d\n", ret);

            auto vm = KVMTraceVCPU::create(ret);
            ret = g_fdm->registerInterface(vm);

            printf("KVMTraceVM::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_CREATE_VCPU", request,
                   arg1, ret);
        } break;

        case KVM_SET_USER_MEMORY_REGION: {
            trace_s2e_kvm_set_user_memory_region((struct kvm_userspace_memory_region *) arg1);
            ret = g_original_ioctl(m_kvm_vm_fd, request, arg1);
        } break;

        case KVM_GET_CLOCK: {
            ret = g_original_ioctl(m_kvm_vm_fd, request, arg1);
            printf("KVMTraceVM::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_CLOCK", request, arg1,
                   ret);
        } break;

        case KVM_SET_CLOCK: {
            ret = g_original_ioctl(m_kvm_vm_fd, request, arg1);
            printf("KVMTraceVM::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_SET_CLOCK", request, arg1,
                   ret);
        } break;

        case KVM_ENABLE_CAP: {
            ret = g_original_ioctl(m_kvm_vm_fd, request, arg1);
            printf("KVMTraceVM::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_ENABLE_CAP", request,
                   arg1, ret);
        } break;

        case KVM_IOEVENTFD: {
            ret = g_original_ioctl(m_kvm_vm_fd, request, arg1);
            printf("KVMTraceVM::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_IOEVENTFD", request, arg1,
                   ret);
            struct kvm_ioeventfd *event = (struct kvm_ioeventfd *) arg1;
            printf("    >kvm_ioeventd datamatch=%#llx addr=%llx len=%d fd=%d flags=%#" PRIx32 "\n", event->datamatch,
                   event->addr, event->len, event->fd, event->flags);

        } break;

        case KVM_SET_IDENTITY_MAP_ADDR: {
            ret = g_original_ioctl(m_kvm_vm_fd, request, arg1);
            printf("KVMTraceVM::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_SET_IDENTITY_MAP_ADDR",
                   request, arg1, ret);
        } break;

        case KVM_GET_DIRTY_LOG: {
            ret = g_original_ioctl(m_kvm_vm_fd, request, arg1);
            printf("KVMTraceVM::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_DIRTY_LOG", request,
                   arg1, ret);
        } break;

        default: {
            printf("KVMTraceVM::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "UNSUPPORTED_API", request,
                   arg1, ret);
        } break;
    }

    return ret;
}

IFilePtr KVMTraceVCPU::create(int vcpu_fd) {
    return std::shared_ptr<KVMTraceVCPU>(new KVMTraceVCPU(vcpu_fd));
}

void *KVMTraceVCPU::sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    return g_original_mmap64(addr, len, prot, flags, m_kvm_vcpu_fd, offset);
}

int KVMTraceVCPU::sys_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_GET_CLOCK: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_CLOCK", request,
                   arg1, ret);
        } break;

        case KVM_SET_CPUID2: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_SET_CPUID2", request,
                   arg1, ret);
        } break;

        case KVM_SET_SIGNAL_MASK: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_SET_SIGNAL_MASK",
                   request, arg1, ret);
        } break;

        /***********************************************/
        case KVM_SET_REGS: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_SET_REGS", request,
                   arg1, ret);
        } break;

        case KVM_SET_FPU: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_SET_FPU", request, arg1,
                   ret);
        } break;

        case KVM_SET_SREGS: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_SET_SREGS", request,
                   arg1, ret);
        } break;

        case KVM_SET_MSRS: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_SET_MSRS", request,
                   arg1, ret);
        } break;

        case KVM_SET_MP_STATE: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_SET_MP_STATE", request,
                   arg1, ret);
        } break;
        /***********************************************/
        case KVM_GET_REGS: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_REGS", request,
                   arg1, ret);
        } break;

        case KVM_GET_FPU: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_FPU", request, arg1,
                   ret);
        } break;

        case KVM_GET_SREGS: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_SREGS", request,
                   arg1, ret);
        } break;

        case KVM_GET_MSRS: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_MSRS", request,
                   arg1, ret);
        } break;

        case KVM_GET_MP_STATE: {
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x arg=%#" PRIx64 " ret=%#x\n", __FUNCTION__, "KVM_GET_MP_STATE", request,
                   arg1, ret);
        } break;

        /***********************************************/
        case KVM_RUN: {
            if (!s_kvm_run) {
                s_kvm_run = (kvm_run *) g_original_mmap(NULL, s_kvm_vcpu_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                                                        m_kvm_vcpu_fd, 0);
                if (s_kvm_run == MAP_FAILED) {
                    printf("Could not map the cpu struct errno=%s\n", strerror(errno));
                    exit(-1);
                }
            }

            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            trace_s2e_kvm_run(s_kvm_run, ret);
        } break;

        case KVM_INTERRUPT: {
            struct kvm_interrupt *interrupt = (struct kvm_interrupt *) arg1;
            ret = g_original_ioctl(m_kvm_vcpu_fd, request, arg1);
            printf("KVMTraceVCPU::%s %s req=%#x irq=%#" PRIx32 " ret=%#x\n", __FUNCTION__, "KVM_INTERRUPT", request,
                   interrupt->irq, ret);
        } break;

        default: {
            printf("KVMTraceVCPU::ioctl vcpu %d request=%#x arg=%#" PRIx64 " ret=%#x\n", fd, request, arg1, ret);
            exit(-1);
        }
    }

    return ret;
}
} // namespace kvm
} // namespace s2e
