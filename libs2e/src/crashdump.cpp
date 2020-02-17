///
/// Copyright (C) 2015-2017, Cyberhaven
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

#include <chrono>
#include <memory>
#include <string.h>

extern "C" {
#include <cpu/cpu-common.h>
#include <cpu/exec.h>
#include <cpu/i386/cpu.h>
#include <cpu/memory.h>
#include <cpu/types.h>

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

extern struct CPUX86State *env;
uintptr_t s2e_get_host_address(target_phys_addr_t paddr);
void generate_crashdump(void);
}

#include <sstream>
#include <vmi/FileProvider.h>
#include <vmi/WindowsCrashDumpGenerator.h>

using namespace vmi;
using namespace vmi::windows;

bool readX86Register(void *opaque, unsigned regIndex, void *buffer, unsigned size) {
    if (regIndex <= X86_GS) {
        switch (regIndex) {
            case X86_EAX:
                memcpy(buffer, &env->regs[R_EAX], size);
                break;
            case X86_EBX:
                memcpy(buffer, &env->regs[R_EBX], size);
                break;
            case X86_ECX:
                memcpy(buffer, &env->regs[R_ECX], size);
                break;
            case X86_EDX:
                memcpy(buffer, &env->regs[R_EDX], size);
                break;
            case X86_ESI:
                memcpy(buffer, &env->regs[R_ESI], size);
                break;
            case X86_EDI:
                memcpy(buffer, &env->regs[R_EDI], size);
                break;
            case X86_ESP:
                memcpy(buffer, &env->regs[R_ESP], size);
                break;
            case X86_EBP:
                memcpy(buffer, &env->regs[R_EBP], size);
                break;

            case X86_CS:
                memcpy(buffer, &env->segs[R_CS], size);
                break;
            case X86_DS:
                memcpy(buffer, &env->segs[R_DS], size);
                break;
            case X86_ES:
                memcpy(buffer, &env->segs[R_ES], size);
                break;
            case X86_SS:
                memcpy(buffer, &env->segs[R_SS], size);
                break;
            case X86_FS:
                memcpy(buffer, &env->segs[R_FS], size);
                break;
            case X86_GS:
                memcpy(buffer, &env->segs[R_GS], size);
                break;
            default:
                assert(false);
        }
        return true;
    } else if (regIndex <= X86_CR4) {
        memcpy(buffer, &env->cr[regIndex - X86_CR0], size);
        return true;
    } else if (regIndex <= X86_DR7) {
        memcpy(buffer, &env->cr[regIndex - X86_DR0], size);
        return true;
    } else if (regIndex == X86_EFLAGS) {
        uint64_t flags = cpu_get_eflags(env);
        memcpy(buffer, &flags, size);
    } else if (regIndex == X86_EIP) {
        memcpy(buffer, &env->eip, size);
    } else {
        return false;
    }

    return true;
}

static uint64_t getPhysicalAddress(uint64_t virtualAddress) {
    target_phys_addr_t physicalAddress = cpu_get_phys_page_debug(env, virtualAddress & TARGET_PAGE_MASK);
    if (physicalAddress == (target_phys_addr_t) -1)
        return (uint64_t) -1;

    return physicalAddress | (virtualAddress & ~TARGET_PAGE_MASK);
}

static uint64_t getHostAddress(uint64_t address) {
    uint64_t phys_addr = getPhysicalAddress(address);
    if (phys_addr == (uint64_t) -1)
        return (uint64_t) -1;

    const MemoryDesc *desc = mem_desc_find(phys_addr);
    if (!desc) {
        return -1;
    }

    uint64_t offset = mem_desc_get_offset(desc, phys_addr);

    return desc->kvm.userspace_addr + offset;
}

bool rwGuestVirtual(void *opaque, uint64_t address, void *buf, unsigned size, bool is_write) {
    while (size > 0) {
        uint64_t hostAddress = getHostAddress(address);
        if (hostAddress == (uint64_t) -1) {
            return false;
        }

        uint64_t hostPage = hostAddress & TARGET_PAGE_MASK;
        uint64_t length = (hostPage + TARGET_PAGE_SIZE) - hostAddress;
        if (length > size) {
            length = size;
        }

#ifdef CONFIG_SYMBEX
        if (is_write) {
            g_sqi.mem.write_ram_concrete(hostAddress, (const uint8_t *) buf, length);
        } else {
            g_sqi.mem.read_ram_concrete(hostAddress, buf, length);
        }
#else
        if (is_write) {
            memcpy((void *) hostAddress, buf, length);
        } else {
            memcpy(buf, (void *) hostAddress, length);
        }
#endif

        buf = (uint8_t *) buf + length;
        address += length;
        size -= length;
    }

    return true;
}

bool readGuestVirtual(void *opaque, uint64_t address, void *buf, unsigned size) {
    return rwGuestVirtual(opaque, address, buf, size, false);
}

bool writeGuestVirtual(void *opaque, uint64_t address, const void *buf, unsigned size) {
    return rwGuestVirtual(opaque, address, (void *) buf, size, true);
}

bool readGuestPhysical(void *opaque, uint64_t address, void *dest, unsigned size) {
    cpu_physical_memory_rw(address, (uint8_t *) dest, size, 0);
    return true;
}

void generate_crashdump(void) {
    extern CPUX86State *env;
    uint64_t KernelNativeBase = 0x400000;

    auto vp = GuestMemoryFileProvider::get(env, readGuestVirtual, writeGuestVirtual, "virt");
    auto pp = GuestMemoryFileProvider::get(env, readGuestPhysical, NULL, "phys");
    X86RegisterProvider rp(env, readX86Register, NULL);

    auto tp = std::chrono::steady_clock::now();
    auto sec = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch());
    std::stringstream ss;
    ss << "crash-" << sec.count() << ".dmp";

    auto fp = FileSystemFileProvider::get(ss.str(), true);
    if (!fp) {
        return;
    }

    auto cgen = WindowsCrashDumpGenerator::get(vp, pp, &rp, fp);

    uint64_t KPCR = 0xffdff000;
    uint64_t KPCRB = KPCR + 0x120;

    uint64_t pKdVersionBlock = KPCR + 0x34;

    uint32_t KdVersionBlock;
    if (vp->read(&KdVersionBlock, sizeof(KdVersionBlock), pKdVersionBlock) != sizeof(KdVersionBlock)) {
        return;
    }

    DBGKD_GET_VERSION64 kdVersion;
    if (vp->read(&kdVersion, sizeof(kdVersion), KdVersionBlock) != sizeof(kdVersion)) {
        return;
    }

    // TODO: auto detect build type
    // WinXP SP3
    //  - free build base is at 0x804d7000
    //  - checked build base is at 0x80a02000

    // ntoskrnl.exe
    // uint64_t KdDebuggerDataBlock = 0x475de0 - KernelNativeBase + kdVersion.KernBase;

    // ntkrnlpa.exe free build
    uint64_t KdDebuggerDataBlock = 0x46eae0 - KernelNativeBase + kdVersion.KernBase;

    // ntkrnlpa.exe checked build
    // uint64_t KdDebuggerDataBlock = 0x004ec3f0 - KernelNativeBase + kdVersion.KernBase;

    CONTEXT32 context;

    context.ContextFlags = CONTEXT_FULL;
    context.Dr0 = env->dr[0];
    context.Dr1 = env->dr[1];
    context.Dr2 = env->dr[2];
    context.Dr3 = env->dr[3];
    context.Dr6 = env->dr[6];
    context.Dr7 = env->dr[7];

    context.SegGs = env->segs[R_GS].selector;
    context.SegFs = env->segs[R_FS].selector;
    context.SegEs = env->segs[R_ES].selector;
    context.SegDs = env->segs[R_DS].selector;
    context.SegCs = env->segs[R_CS].selector;
    context.SegSs = env->segs[R_SS].selector;

    context.Eax = env->regs[R_EAX];
    context.Ebx = env->regs[R_EBX];
    context.Ecx = env->regs[R_ECX];
    context.Edx = env->regs[R_EDX];
    context.Edi = env->regs[R_EDI];
    context.Esi = env->regs[R_ESI];
    context.Esp = env->regs[R_ESP];
    context.Ebp = env->regs[R_EBP];
    context.Eip = env->eip;
    context.EFlags = env->mflags;

    BugCheckDescription bugDesc;
    vp->read(&bugDesc.code, sizeof(uint32_t), env->regs[R_ESP] + 4);
    for (int i = 0; i < 4; ++i) {
        vp->read(&bugDesc.parameters[i], sizeof(uint32_t), env->regs[R_ESP] + 4 + (i + 1) * 4);
    }

    cgen->generate(KdDebuggerDataBlock, KPCRB, kdVersion, context, bugDesc);
}
