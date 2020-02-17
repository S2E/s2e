///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
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

#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <vmi/FileProvider.h>
#include <vmi/RegisterProvider.h>
#include <vmi/WindowsCrashDumpGenerator.h>

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#include <iostream>
#include <sstream>

#include "BlueScreenInterceptor.h"
#include "WindowsCrashDumpGenerator.h"

static s2e::plugins::WindowsCrashDumpGenerator *s_bsod;

extern "C" {
void s2e_win_crash_dump(void) {
    std::string path = s_bsod->getPathForDump(g_s2e_state);

    vmi::windows::BugCheckDescription desc;
    s_bsod->generateManualDump(g_s2e_state, path, &desc);
}
}

namespace s2e {
namespace plugins {

using namespace vmi::windows;

S2E_DEFINE_PLUGIN(WindowsCrashDumpGenerator, "Generates WinDbg-compatible crash dumps", "WindowsCrashDumpGenerator",
                  "WindowsMonitor");

void WindowsCrashDumpGenerator::initialize() {
    // Register the LUA API for crash dump generation
    Lunar<WindowsCrashDumpInvoker>::Register(s2e()->getConfig()->getState());

    m_monitor = s2e()->getPlugin<WindowsMonitor>();
    s_bsod = this;
}

bool WindowsCrashDumpGenerator::generateManualDump(S2EExecutionState *state, const std::string &filename,
                                                   const BugCheckDescription *info) {
    BugCheckDescription newInfo = *info;
    newInfo.code = 0xDEADDEAD; // MANUALLY_INITIATED_CRASH1

    CONTEXT32 context;
    getContext32(state, context);
    context.Eip = state->regs()->getPc();

    return generateCrashDump(state, filename, &newInfo, context);
}

bool WindowsCrashDumpGenerator::generateDump(S2EExecutionState *state, const std::string &filename,
                                             const BugCheckDescription *info) {
    CONTEXT32 context;
    getContext32(state, context);

    return generateCrashDump(state, filename, info, context);
}

bool WindowsCrashDumpGenerator::generateCrashDump(S2EExecutionState *state, const std::string &filename,
                                                  const BugCheckDescription *bugDesc, const CONTEXT32 &context) {
    getDebugStream(state) << "generating dump in " << filename << "\n";

    auto fp = vmi::FileSystemFileProvider::get(filename, true);
    if (!fp) {
        getWarningsStream(state) << "could not open " << filename << " for writing - " << strerror(errno) << "\n";
        return false;
    }

    auto physicalMemory = vmi::GuestMemoryFileProvider::get(state, &Vmi::readGuestPhysical, nullptr, filename);
    auto virtualMemory =
        vmi::GuestMemoryFileProvider::get(state, &Vmi::readGuestVirtual, &Vmi::writeGuestVirtual, filename);

    vmi::X86RegisterProvider registers(state, &Vmi::readX86Register, nullptr);

    auto crashGen = vmi::windows::WindowsCrashDumpGenerator::get(virtualMemory, physicalMemory, &registers, fp);

    bool retd = false;

    if (bugDesc->guestHeader) {
        if (state->getPointerSize() == 4) {
            CONTEXT32 context;
            getContext32(state, context);
            retd = crashGen->generate(*bugDesc, &context, sizeof(context));
        } else {
            CONTEXT64 context;
            getContext64(state, context);
            retd = crashGen->generate(*bugDesc, &context, sizeof(context));
        }
    } else {
        retd = crashGen->generate(m_monitor->getKdDebuggerDataBlock(), m_monitor->getKprcbAddress(),
                                  m_monitor->getVersionBlock(), context, *bugDesc);
    }

    if (!retd) {
        getDebugStream(state) << "could not generated dump\n";
        return false;
    }

    uint64_t size;
    std::error_code error = llvm::sys::fs::file_size(filename, size);
    if (error) {
        getWarningsStream(state) << "Unable to determine size of " << filename << " - " << error.message() << '\n';
        return false;
    } else {
        getDebugStream(state) << "dump size " << hexval(size) << "\n";
    }

    return true;
}

const char WindowsCrashDumpInvoker::className[] = "WindowsCrashDumpInvoker";

Lunar<WindowsCrashDumpInvoker>::RegType WindowsCrashDumpInvoker::methods[] = {
    LUNAR_DECLARE_METHOD(WindowsCrashDumpInvoker, generateCrashDump), {0, 0}};

WindowsCrashDumpInvoker::WindowsCrashDumpInvoker(WindowsCrashDumpGenerator *plg) {
    m_plugin = plg;
}

WindowsCrashDumpInvoker::WindowsCrashDumpInvoker(lua_State *lua) {
    m_plugin = g_s2e->getPlugin<WindowsCrashDumpGenerator>();
}

WindowsCrashDumpInvoker::~WindowsCrashDumpInvoker() {
}

int WindowsCrashDumpInvoker::generateCrashDump(lua_State *L) {
    llvm::raw_ostream &os = g_s2e->getDebugStream();

    if (!lua_isstring(L, 1)) {
        os << "First argument to " << __FUNCTION__ << " must be the prefix of the crash dump" << '\n';
        return 0;
    }

    std::string prefix = luaL_checkstring(L, 1);

    S2EExecutionState *state = g_s2e_state;
    int stateId = g_s2e_state->getID();
    if (lua_isnumber(L, 2)) {
        stateId = lua_tointeger(L, 2);
        state = nullptr;

        // Fetch the right state
        // XXX: Avoid linear search
        const klee::StateSet &states = g_s2e->getExecutor()->getStates();
        foreach2 (it, states.begin(), states.end()) {
            S2EExecutionState *ss = static_cast<S2EExecutionState *>(*it);
            if (ss->getID() == stateId) {
                state = ss;
                break;
            }
        }
    }

    if (state == nullptr) {
        os << "State with id " << stateId << " does not exist" << '\n';
        return 0;
    }

    if (!m_plugin) {
        os << "Please enable the WindowsCrashDumpGenerator plugin in your configuration file" << '\n';
        return 0;
    }

    std::string path = m_plugin->getPathForDump(state);

    BugCheckDescription desc;
    m_plugin->generateManualDump(state, path, &desc);

    return 0;
}

std::string WindowsCrashDumpGenerator::getPathForDump(S2EExecutionState *state, const std::string &prefix) {
    std::stringstream filename;
    filename << prefix << state->getID() << ".dmp";

    return g_s2e->getOutputFilename(filename.str());
}

template <typename T> void WindowsCrashDumpGenerator::getContext(S2EExecutionState *state, T &Context) {
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

    Context.EFlags = state->regs()->getFlags();
}

void WindowsCrashDumpGenerator::getContext32(S2EExecutionState *state, vmi::windows::CONTEXT32 &Context) {
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

    Context.Eip = (uint32_t) state->regs()->getPc();
}

void WindowsCrashDumpGenerator::getContext64(S2EExecutionState *state, vmi::windows::CONTEXT64 &Context) {
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

    Context.Rip = state->regs()->getPc();
}

} // namespace plugins
} // namespace s2e
