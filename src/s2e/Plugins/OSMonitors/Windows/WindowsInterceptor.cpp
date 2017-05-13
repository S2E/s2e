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

vmi::PEFile *WindowsInterceptor::getPEFile(S2EExecutionState *state, const ModuleDescriptor &Desc) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return NULL;
    }

    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);

    // XXX: PEFile retains reference to local "file" variable; we trust it will
    // never use it after initialization.
    return vmi::PEFile::get(&file, true, Desc.LoadBase);
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

    Context.Rip = state->getPc();
}
}
}
