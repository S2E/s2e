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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/cpu.h>

#include <vmi/Pe.h>

#include "BlueScreenInterceptor.h"
#include "WindowsCrashDumpGenerator.h"

#include <iomanip>
#include <sstream>

using namespace vmi::windows;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(BlueScreenInterceptor, "Intercepts Windows blue screens of death and generated bug reports",
                  "BlueScreenInterceptor", "WindowsMonitor");

void BlueScreenInterceptor::initialize() {
    m_monitor = s2e()->getPlugin<WindowsMonitor>();
    if (!m_monitor) {
        getWarningsStream() << "you must use a Windows monitor plugin\n";
        exit(-1);
    }

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &BlueScreenInterceptor::onTranslateBlockStart));
}

void BlueScreenInterceptor::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                  TranslationBlock *tb, uint64_t pc) {
    if (!m_monitor->CheckPanic(pc)) {
        return;
    }

    signal->connect(sigc::mem_fun(*this, &BlueScreenInterceptor::onBsod));
}

bool BlueScreenInterceptor::invokeCrashRoutine(S2EExecutionState *state, uint64_t pc) {
    uint64_t crashRoutine = m_monitor->getCrashRedirectionRoutine();
    if (!crashRoutine) {
        return false;
    }

    state->regs()->setPc(crashRoutine);
    throw CpuExitException();

    /* We don't return */
    return true;
}

void BlueScreenInterceptor::onBsod(S2EExecutionState *state, uint64_t pc) {
    std::stringstream ss;

    getDebugStream(state) << "caught blue screen\n";

    if (invokeCrashRoutine(state, pc)) {
        return;
    }

    /* Retrive bug check info */
    /* XXX: 64-bits guests! */
    uint32_t code;
    uint64_t param1, param2, param3, param4;

#ifdef TARGET_X86_64
    if (state->getPointerSize() == 4)
#endif
    {
        bool ok = true;
        uint32_t _code, _param1, _param2, _param3, _param4;
        ok &= OSMonitor::readConcreteParameter<uint32_t>(state, 0, &_code);
        ok &= OSMonitor::readConcreteParameter<uint32_t>(state, 1, &_param1);
        ok &= OSMonitor::readConcreteParameter<uint32_t>(state, 2, &_param2);
        ok &= OSMonitor::readConcreteParameter<uint32_t>(state, 3, &_param3);
        ok &= OSMonitor::readConcreteParameter<uint32_t>(state, 4, &_param4);
        code = _code;
        param1 = _param1;
        param2 = _param2;
        param3 = _param3;
        param4 = _param4;
    }
#ifdef TARGET_X86_64
    else {
        code = state->regs()->read<uint32_t>(CPU_OFFSET(regs[R_ECX]));
        param1 = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EDX]));
        param2 = state->regs()->read<uint64_t>(CPU_OFFSET(regs[8]));
        param3 = state->regs()->read<uint64_t>(CPU_OFFSET(regs[9]));
        OSMonitor::readConcreteParameter<uint64_t>(state, 4, &param4);
    }
#endif

    BugCheckDescription info;
    info.code = code;
    info.parameters[0] = param1;
    info.parameters[1] = param2;
    info.parameters[2] = param3;
    info.parameters[3] = param4;
    info.headerSize = 0;

    onBlueScreen.emit(state, &info);

    ss << "BSOD: code=" << hexval(code) << " param1=" << hexval(param1) << " param2=" << hexval(param2)
       << " param3=" << hexval(param3) << " param4=" << hexval(param4);

    s2e()->getExecutor()->terminateState(*state, ss.str());
}

void BlueScreenInterceptor::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                                   uint64_t guestDataSize) {
    S2E_BSOD_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_BSOD_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    BugCheckDescription info;
    info.code = command.Code;
    info.parameters[0] = command.Parameters[0];
    info.parameters[1] = command.Parameters[1];
    info.parameters[2] = command.Parameters[2];
    info.parameters[3] = command.Parameters[3];

    if (command.Header && command.HeaderSize <= 0x10000) {
        info.guestHeader = command.Header;
        info.headerSize = command.HeaderSize;
    }

    std::stringstream ss;
    ss << "BSOD: code=" << hexval(command.Code) << " param1=" << hexval(command.Parameters[0])
       << " param2=" << hexval(command.Parameters[1]) << " param3=" << hexval(command.Parameters[2])
       << " param4=" << hexval(command.Parameters[3]);

    onBlueScreen.emit(state, &info);

    s2e()->getExecutor()->terminateState(*state, ss.str());
}
} // namespace plugins
} // namespace s2e
