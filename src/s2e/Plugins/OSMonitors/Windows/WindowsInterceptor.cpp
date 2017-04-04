///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/S2E.h>
#include <vmi/FileProvider.h>
#include <vmi/PEFile.h>

#include "WindowsInterceptor.h"

namespace s2e {
namespace plugins {

bool WindowsInterceptor::patchImportsFromDisk(S2EExecutionState *state, const ModuleDescriptor &module,
                                              uint32_t checkSum, vmi::Imports &imports) {
    bool result = true;
    getDebugStream(state) << "trying to open the on-disk image to parse imports\n";
    Vmi *vmi = static_cast<Vmi *>(s2e()->getPlugin("Vmi"));
    if (!vmi) {
        getDebugStream(state) << "vmi plugin not loaded\n";
        return false;
    }

    Vmi::PeData pd = vmi->getPeFromDisk(module, true);
    if (!pd.pe) {
        getDebugStream(state) << "could not find on-disk image\n";
        return false;
    }

    if (checkSum != pd.pe->getCheckSum()) {
        getDebugStream(state) << "checksum mismatch for " << module.Name << "\n";
        result = false;
        goto err1;
    }

    imports = pd.pe->getImports();

    for (vmi::Imports::iterator it = imports.begin(); it != imports.end(); ++it) {
        vmi::ImportedSymbols &symbols = (*it).second;

        for (vmi::ImportedSymbols::iterator fit = symbols.begin(); fit != symbols.end(); ++fit) {
            uint64_t itl = (*fit).second.importTableLocation + module.LoadBase;
            uint64_t address = (*fit).second.address;

            if (!state->readPointer(itl, address)) {
                getWarningsStream(state) << "could not read address " << hexval(itl) << "\n";
                continue;
            }

            (*fit).second.importTableLocation = itl;
            (*fit).second.address = address;
        }
    }

err1:
    delete pd.pe;
    delete pd.fp;
    return result;
}

vmi::PEFile *WindowsInterceptor::getPEFile(S2EExecutionState *state, const ModuleDescriptor &Desc) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return NULL;
    }

    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);

    // XXX: PEFile retains reference to local "file" variable; we trust it will
    // never use it after initialization.
    return vmi::PEFile::get(&file, true, Desc.LoadBase);
}

bool WindowsInterceptor::getEntryPoint(S2EExecutionState *state, const ModuleDescriptor &Desc, uint64_t &Addr) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return false;
    }

    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);
    vmi::PEFile *image = vmi::PEFile::get(&file, true, Desc.LoadBase);
    if (!image) {
        return false;
    }

    Addr = image->getEntryPoint();
    return true;
}

bool WindowsInterceptor::getImports(S2EExecutionState *state, const ModuleDescriptor &Desc, vmi::Imports &I) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return false;
    }

    getDebugStream(state) << "getting import for " << Desc << "\n";

    bool result = true;
    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);
    vmi::PEFile *image = vmi::PEFile::get(&file, true, Desc.LoadBase);
    if (!image) {
        return false;
    }

    /**
     * If the import table is in the INIT section, it's likely that the OS
     * unloaded it. Instead of failing, reconstruct the import table from
     * the original binary.
     */
    if (patchImportsFromDisk(state, Desc, image->getCheckSum(), I)) {
        goto end;
    }

    I = image->getImports();

end:
    delete image;
    return result;
}

bool WindowsInterceptor::getExports(S2EExecutionState *state, const ModuleDescriptor &Desc, vmi::Exports &E) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return false;
    }

    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);
    vmi::PEFile *image = vmi::PEFile::get(&file, true, Desc.LoadBase);
    if (!image) {
        return false;
    }

    E = image->getExports();
    delete image;
    return true;
}

bool WindowsInterceptor::getRelocations(S2EExecutionState *state, const ModuleDescriptor &Desc, vmi::Relocations &R) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return false;
    }

    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);
    vmi::PEFile *image = vmi::PEFile::get(&file, true, Desc.LoadBase);
    if (!image) {
        return false;
    }

    R = image->getRelocations();
    delete image;
    return true;
}

bool WindowsInterceptor::getSections(S2EExecutionState *state, const ModuleDescriptor &Desc, vmi::Sections &S) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return false;
    }

    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);
    vmi::PEFile *image = vmi::PEFile::get(&file, true, Desc.LoadBase);
    if (!image) {
        return false;
    }

    S = image->getSections();
    delete image;
    return true;
}

template <typename T> void WindowsInterceptor::getContext(S2EExecutionState *state, T &Context) {
    memset(&Context, 0x0, sizeof(Context));
    S2EExecutionStateRegisters *regs = state->regs();

    Context.ContextFlags = CONTEXT_FULL;
    Context.Dr0 = regs->read<target_ulong>(offsetof(CPUX86State, dr[0]));
    Context.Dr1 = regs->read<target_ulong>(offsetof(CPUX86State, dr[1]));
    Context.Dr2 = regs->read<target_ulong>(offsetof(CPUX86State, dr[2]));
    Context.Dr3 = regs->read<target_ulong>(offsetof(CPUX86State, dr[3]));
    Context.Dr6 = regs->read<target_ulong>(offsetof(CPUX86State, dr[6]));
    Context.Dr7 = regs->read<target_ulong>(offsetof(CPUX86State, dr[7]));

    Context.SegDs = regs->read<target_ulong>(offsetof(CPUX86State, segs[R_DS]));
    Context.SegEs = regs->read<target_ulong>(offsetof(CPUX86State, segs[R_ES]));
    Context.SegFs = regs->read<target_ulong>(offsetof(CPUX86State, segs[R_FS]));
    Context.SegGs = regs->read<target_ulong>(offsetof(CPUX86State, segs[R_GS]));

    Context.SegCs = regs->read<target_ulong>(offsetof(CPUX86State, segs[R_CS]));
    Context.SegSs = regs->read<target_ulong>(offsetof(CPUX86State, segs[R_SS]));

    Context.EFlags = state->getFlags();
}

void WindowsInterceptor::getContext32(S2EExecutionState *state, vmi::windows::CONTEXT32 &Context) {
    getContext(state, Context);

    S2EExecutionStateRegisters *regs = state->regs();

    Context.ContextFlags = CONTEXT_FULL;

    Context.Eax = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_EAX]));
    Context.Ebx = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_EBX]));
    Context.Ecx = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_ECX]));
    Context.Edx = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_EDX]));
    Context.Esi = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_ESI]));
    Context.Edi = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_EDI]));
    Context.Esp = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_ESP]));
    Context.Ebp = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_EBP]));

    Context.Eip = (uint32_t) state->getPc();
}

void WindowsInterceptor::getContext64(S2EExecutionState *state, vmi::windows::CONTEXT64 &Context) {
    getContext(state, Context);

    S2EExecutionStateRegisters *regs = state->regs();

    Context.ContextFlags = CONTEXT_FULL;

    Context.Rax = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_EAX]));
    Context.Rbx = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_EBX]));
    Context.Rcx = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_ECX]));
    Context.Rdx = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_EDX]));
    Context.Rsi = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_ESI]));
    Context.Rdi = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_EDI]));
    Context.Rsp = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_ESP]));
    Context.Rbp = regs->read<target_ulong>(offsetof(CPUX86State, regs[R_EBP]));

    Context.Rip = (uint32_t) state->getPc();
}
}
}
