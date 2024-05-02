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

#include <sstream>
#include <string.h>

#include <cpu/cpus.h>
#include <cpu/exec.h>
#include <cpu/memory.h>
#include <tcg/utils/log.h>
#include <timer.h>

#include <cpu/cpu-common.h>
#include <cpu/i386/cpu.h>
#include <cpu/ioport.h>
#include <cpu/kvm.h>

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#include <s2e/monitor.h>
#include <s2e/s2e_block.h>
#include <s2e/s2e_config.h>
#include <s2e/s2e_libcpu.h>
#include <tcg/tcg-llvm.h>
#endif

#include "libs2e.h"
#include "s2e-kvm-vm.h"
#include "s2e-kvm.h"

extern void *g_s2e;
extern bool g_execute_always_klee;

extern CPUX86State *env;

namespace s2e {
namespace kvm {

static std::shared_ptr<S2EKVM> s_s2e_kvm;
struct stats_t g_stats;

static const int MAX_MEMORY_SLOTS = 32;

// clang-format off
static uint32_t s_msr_list [] = {
    MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_EIP,
    MSR_IA32_APICBASE,
    MSR_EFER,
    MSR_STAR,
    MSR_PAT,
    MSR_VM_HSAVE_PA,
    #ifdef TARGET_X86_64
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_FMASK,
    MSR_FSBASE,
    MSR_GSBASE,
    MSR_KERNELGSBASE,
    #endif
    MSR_MTRRphysBase(0),
    MSR_MTRRphysBase(1),
    MSR_MTRRphysBase(2),
    MSR_MTRRphysBase(3),
    MSR_MTRRphysBase(4),
    MSR_MTRRphysBase(5),
    MSR_MTRRphysBase(6),
    MSR_MTRRphysBase(7),
    MSR_MTRRphysMask(0),
    MSR_MTRRphysMask(1),
    MSR_MTRRphysMask(2),
    MSR_MTRRphysMask(3),
    MSR_MTRRphysMask(4),
    MSR_MTRRphysMask(5),
    MSR_MTRRphysMask(6),
    MSR_MTRRphysMask(7),
    MSR_MTRRfix64K_00000,
    MSR_MTRRfix16K_80000,
    MSR_MTRRfix16K_A0000,
    MSR_MTRRfix4K_C0000,
    MSR_MTRRfix4K_C8000,
    MSR_MTRRfix4K_D0000,
    MSR_MTRRfix4K_D8000,
    MSR_MTRRfix4K_E0000,
    MSR_MTRRfix4K_E8000,
    MSR_MTRRfix4K_F0000,
    MSR_MTRRfix4K_F8000,
    MSR_MTRRdefType,
    MSR_MCG_STATUS,
    MSR_MCG_CTL,
    MSR_TSC_AUX,
    MSR_IA32_MISC_ENABLE,
    MSR_MC0_CTL,
    MSR_MC0_STATUS,
    MSR_MC0_ADDR,
    MSR_MC0_MISC
};

#define KVM_CPUID_SIGNATURE 0x40000000
#define KVM_CPUID_FEATURES 0x40000001
#define KVM_FEATURE_CLOCKSOURCE 0

/* Array of valid (function, index) entries */
static uint32_t s_cpuid_entries[][2] = {
    {0, (uint32_t) -1},
    {1, (uint32_t) -1},
    {2, (uint32_t) -1},
    {4, 0},
    {4, 1},
    {4, 2},
    {4, 3},
    {5, (uint32_t) -1},
    {6, (uint32_t) -1},
    {7, (uint32_t) -1},
    {9, (uint32_t) -1},
    {0xa, (uint32_t) -1},
    {0xd, (uint32_t) -1},
    {KVM_CPUID_SIGNATURE, (uint32_t) -1},
    {KVM_CPUID_FEATURES, (uint32_t) -1},
    {0x80000000, (uint32_t) -1},
    {0x80000001, (uint32_t) -1},
    {0x80000002, (uint32_t) -1},
    {0x80000003, (uint32_t) -1},
    {0x80000004, (uint32_t) -1},
    {0x80000005, (uint32_t) -1},
    {0x80000006, (uint32_t) -1},
    {0x80000008, (uint32_t) -1},
    {0x8000000a, (uint32_t) -1},
    {0xc0000000, (uint32_t) -1},
    {0xc0000001, (uint32_t) -1},
    {0xc0000002, (uint32_t) -1},
    {0xc0000003, (uint32_t) -1},
    {0xc0000004, (uint32_t) -1}
};
// clang-format on

#if defined(TARGET_X86_64)
const char *S2EKVM::s_cpuModel = "qemu64-s2e";
const bool S2EKVM::s_is64 = true;
#elif defined(TARGET_I386)
const char *S2EKVM::s_cpuModel = "qemu32-s2e";
const bool S2EKVM::s_is64 = false;
#else
#error unknown architecture
#endif

IFilePtr S2EKVM::create() {
    auto ret = std::shared_ptr<S2EKVM>(new S2EKVM());
    ret->init();
    s_s2e_kvm = ret;
    return ret;
}

void S2EKVM::cleanup(void) {
    s_s2e_kvm->m_exiting = true;

    while (!s_s2e_kvm->m_timerExited) {
    }

#ifdef CONFIG_SYMBEX
    if (g_s2e) {
        monitor_close();
        s2e_close();
        g_s2e = nullptr;
        s_s2e_kvm = nullptr;
    }
#endif
}

#ifdef CONFIG_SYMBEX
std::string S2EKVM::getBitcodeLibrary(const std::string &dir) {
#ifdef CONFIG_SYMBEX_MP
    std::string name = "op_helper.bc." TARGET_ARCH;
#else
    std::string name = "op_helper_sp.bc." TARGET_ARCH;
#endif

    std::stringstream ss;
    ss << dir << "/" << name;
    auto ret = ss.str();
    if (access(ret.c_str(), R_OK)) {
        fprintf(stderr,
                "Could not find %s.\n"
                "Make sure that the environment variable S2E_SHARED_DIR is set properly.\n",
                ret.c_str());
        exit(-1);
    }

    return ret;
}
#endif

void S2EKVM::init(void) {
    x86_cpudef_setup();
    printf("Initializing %s cpu\n", s_cpuModel);
    if (cpu_x86_register(&m_cpuid, s_cpuModel, s_is64) < 0) {
        fprintf(stderr, "Could not register CPUID for model %s\n", s_cpuModel);
        exit(-1);
    }

    initLogLevel();

#ifdef CONFIG_SYMBEX
    const char *shared_dir = getenv("S2E_SHARED_DIR");
    if (!shared_dir) {
        fprintf(stderr,
                "Warning: S2E_SHARED_DIR environment variable was not specified, "
                "using %s\n",
                CONFIG_LIBCPU_DATADIR);
        shared_dir = CONFIG_LIBCPU_DATADIR;
    }

    auto config_file = getenv("S2E_CONFIG");

    if (!config_file) {
        fprintf(stderr, "Warning: S2E_CONFIG environment variable was not specified, "
                        "using the default (empty) config file\n");
    }

    auto always_klee = getenv("S2E_ALWAYS_KLEE");
    if (always_klee) {
        if (!strcmp(always_klee, "1")) {
            g_execute_always_klee = true;
        }
    }

    auto output_dir = getenv("S2E_OUTPUT_DIR");

    auto bc = getBitcodeLibrary(shared_dir);
    fprintf(stdout, "Using module %s\n", bc.c_str());
    tcg_llvm_translator = TCGLLVMTranslator::create(bc);

    if (monitor_init() < 0) {
        exit(-1);
    }

    int unbuffered_stream = 0;
    const char *us = getenv("S2E_UNBUFFERED_STREAM");
    if (us && us[0] == '1') {
        unbuffered_stream = 1;
    }

    int max_processes = 1;
    const char *max_processes_str = getenv("S2E_MAX_PROCESSES");
    if (max_processes_str) {
        max_processes = strtol(max_processes_str, NULL, 0);
    }

    init_s2e_libcpu_interface(&g_sqi);

    int argc = 0;
    char **argv = {NULL};

    s2e_initialize(argc, argv, tcg_llvm_translator, config_file, output_dir, unbuffered_stream, 0, max_processes,
                   shared_dir);

    // Call it twice, because event pointers are only known
    // after s2e is inited.
    init_s2e_libcpu_interface(&g_sqi);

    s2e_create_initial_state();
#endif

    atexit(cleanup);
}

///
/// \brief s2e_kvm_init_log_level initializes the libcpu log level.
///
/// This is the same as the -d switch from vanilla QEMU.
///
void S2EKVM::initLogLevel(void) {
    loglevel = 0;
    const char *libcpu_log_level = getenv("LIBCPU_LOG_LEVEL");
    if (libcpu_log_level) {
        loglevel = cpu_str_to_log_mask(libcpu_log_level);
    }

    const char *libcpu_log_file = getenv("LIBCPU_LOG_FILE");
    if (libcpu_log_file) {
        logfile = fopen(libcpu_log_file, "w");
        if (!logfile) {
            printf("Could not open log file %s\n", libcpu_log_file);
            exit(-1);
        }
    } else {
        logfile = stdout;
    }
}

int S2EKVM::getApiVersion(void) {
    return KVM_API_VERSION;
}

int S2EKVM::checkExtension(int capability) {
    switch (capability) {
        case KVM_CAP_NR_MEMSLOTS: {
            return MAX_MEMORY_SLOTS;
        } break;

        case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
        case KVM_CAP_MP_STATE:
        case KVM_CAP_EXT_CPUID:
        case KVM_CAP_SET_TSS_ADDR:
        case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
        case KVM_CAP_USER_MEMORY:
        case KVM_CAP_NR_VCPUS:
        case KVM_CAP_MAX_VCPUS:

        // We don't really need to support this call, just pretend that we do.
        // The real exit will be done through our custom KVM_CAP_FORCE_EXIT.
        case KVM_CAP_IMMEDIATE_EXIT:

        /* libs2e-specific calls */
        case KVM_CAP_DBT:
        case KVM_CAP_MEM_RW:
        case KVM_CAP_FORCE_EXIT:
            return 1;

#ifdef CONFIG_SYMBEX
        case KVM_CAP_MEM_FIXED_REGION:
        case KVM_CAP_DISK_RW:
        case KVM_CAP_CPU_CLOCK_SCALE:
            return 1;
#endif

// Per-path disk state support is only available with symbex builds.
// Can't write snapshot files there.
#ifdef CONFIG_SYMBEX_MP
        case KVM_CAP_DEV_SNAPSHOT:
            return 1;
#endif

        case KVM_CAP_ADJUST_CLOCK:
            return KVM_CLOCK_TSC_STABLE;

#ifdef CONFIG_SYMBEX
        case KVM_CAP_UPCALLS:
            return 1;
#endif

        default:
#ifdef SE_KVM_DEBUG_INTERFACE
            printf("Unsupported cap %x\n", capability);
#endif
            return -1;
    }
}

int S2EKVM::createVM() {
    if (m_vm) {
        // Only allow one VM for now
        return -1;
    }

    auto kvm = std::dynamic_pointer_cast<S2EKVM>(g_fdm->get(this));
    assert(kvm && kvm.get() == this);

    auto vm = VM::create(kvm);
    if (!vm) {
        return -1;
    }

    m_vm = vm;

    if (initTimerThread() < 0) {
        exit(-1);
    }

    return g_fdm->registerInterface(vm);
}

int S2EKVM::getVCPUMemoryMapSize(void) {
    return 0x10000; /* Some magic value */
}

int S2EKVM::getMSRIndexList(struct kvm_msr_list *list) {
    if (list->nmsrs == 0) {
        list->nmsrs = sizeof(s_msr_list) / sizeof(s_msr_list[0]);
    } else {
        for (int i = 0; i < list->nmsrs; ++i) {
            list->indices[i] = s_msr_list[i];
        }
    }

    return 0;
}

int S2EKVM::getSupportedCPUID(struct kvm_cpuid2 *cpuid) {
#ifdef SE_KVM_DEBUG_CPUID
    printf("%s\n", __FUNCTION__);
#endif

    unsigned int nentries = sizeof(s_cpuid_entries) / sizeof(s_cpuid_entries[0]);
    if (cpuid->nent < nentries) {
        errno = E2BIG;
        return -1;
    } else if (cpuid->nent >= nentries) {
        cpuid->nent = nentries;
    }

    for (unsigned i = 0; i < nentries; ++i) {
        struct kvm_cpuid_entry2 *e = &cpuid->entries[i];

        // KVM-specific CPUIDs go here rather than to cpu_x86_cpuid
        // because we don't want to expose them to the guest.
        switch (s_cpuid_entries[i][0]) {
            case KVM_CPUID_SIGNATURE:
                // This returns "KVMKVMVKM"
                e->eax = 0x40000001;
                e->ebx = 0x4b4d564b;
                e->ecx = 0x564b4d56;
                e->edx = 0x4d;
                break;

            case KVM_CPUID_FEATURES:
                // Unlike QEMU 1.0, QEMU 3.0 required this CPUID flag to be set
                // in order to use get/set clock. Not implementing this feature
                // may cause guests to hang on resume because the TSC is not
                // restored in that case.
                e->eax = 1 << KVM_FEATURE_CLOCKSOURCE;
                break;
            default:
                cpu_x86_cpuid(&m_cpuid, s_cpuid_entries[i][0], s_cpuid_entries[i][1], &e->eax, &e->ebx, &e->ecx,
                              &e->edx);
                break;
        }

        e->flags = 0;
        e->index = 0;
        if (s_cpuid_entries[i][1] != -1) {
            e->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
            e->index = s_cpuid_entries[i][1];
        }
        e->function = s_cpuid_entries[i][0];

#ifdef SE_KVM_DEBUG_CPUID
        print_cpuid2(e);
#endif
    }

    return 0;
}

void S2EKVM::sendCpuExitSignal() {
    assert(m_vm);
    m_vm->sendCpuExitSignal();
}

void *S2EKVM::timerCb(void *param) {
    auto obj = reinterpret_cast<S2EKVM *>(param);

    while (!obj->m_exiting) {
        usleep(100 * 1000);

        // Send a signal to exit CPU loop only when no slow KLEE code
        // is running. Otherwise, there are too many exits and little
        // progress in the guest.
        if (timers_state.cpu_clock_scale_factor == 1) {
            // Required for shutdown, otherwise kvm clients may get stuck
            // Also required to give a chance timers to run

            obj->sendCpuExitSignal();
        }
    }

    obj->m_timerExited = true;
    return nullptr;
}

int S2EKVM::initTimerThread(void) {
    int ret;
    pthread_attr_t attr;
    sigset_t signals;

    ret = pthread_attr_init(&attr);
    if (ret < 0) {
        fprintf(stderr, "Could not init thread attributes\n");
        goto err1;
    }

    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret < 0) {
        fprintf(stderr, "Could not set detached state for thread\n");
        goto err1;
    }

    ret = pthread_create(&m_timerThread, &attr, timerCb, this);
    if (ret < 0) {
        fprintf(stderr, "could not create timer thread\n");
        goto err1;
    }

    sigfillset(&signals);
    if (pthread_sigmask(SIG_BLOCK, &signals, NULL) < 0) {
        fprintf(stderr, "could not block signals on the timer thread\n");
        goto err1;
    }

    pthread_attr_destroy(&attr);

err1:
    return ret;
}

int S2EKVM::sys_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;

    switch ((uint32_t) request) {
        case KVM_GET_API_VERSION:
            return getApiVersion();

        case KVM_CHECK_EXTENSION:
            ret = checkExtension(arg1);
            if (ret < 0) {
                errno = 1;
            }
            break;

        case KVM_CREATE_VM: {
            ret = createVM();
            if (ret < 0) {
                printf("Could not create vm fd (errno=%d %s)\n", errno, strerror(errno));
                exit(-1);
            }
        } break;

        case KVM_GET_VCPU_MMAP_SIZE: {
            ret = getVCPUMemoryMapSize();
        } break;

        case KVM_GET_MSR_INDEX_LIST: {
            ret = getMSRIndexList((kvm_msr_list *) arg1);
        } break;

        case KVM_GET_SUPPORTED_CPUID: {
            ret = getSupportedCPUID((kvm_cpuid2 *) arg1);
        } break;

#ifdef CONFIG_SYMBEX
        case KVM_REGISTER_UPCALLS: {
            auto upcalls = (kvm_dev_upcalls *) arg1;
            g_sqi.upcalls.screendump = upcalls->screendump;
            ret = 0;
        } break;
#endif

        default: {
            fprintf(stderr, "libs2e: unknown KVM IOCTL %x\n", request);
            exit(-1);
        }
    }

    return ret;
}
} // namespace kvm
} // namespace s2e
