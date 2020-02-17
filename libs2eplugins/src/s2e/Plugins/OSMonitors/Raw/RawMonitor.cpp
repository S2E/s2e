///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
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

/**
 *  This plugin provides the means of manually specifying the location
 *  of modules in memory.
 *
 *  This allows things like defining poritions of the BIOS.
 *
 *  RESERVES THE CUSTOM OPCODE 0xAA
 */

#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include "RawMonitor.h"

#include <sstream>

using namespace std;

using namespace s2e;
using namespace s2e::plugins;

S2E_DEFINE_PLUGIN(RawMonitor, "Plugin for monitoring raw module events", "OSMonitor");

RawMonitor::~RawMonitor() {
}

bool RawMonitor::initSection(const std::string &cfgKey, const std::string &svcId) {
    Cfg cfg;

    bool ok;
    cfg.name = s2e()->getConfig()->getString(cfgKey + ".name", "", &ok);
    if (!ok) {
        getWarningsStream() << "You must specify " << cfgKey << ".name\n";
        return false;
    }

    cfg.size = s2e()->getConfig()->getInt(cfgKey + ".size", 0, &ok);
    if (!ok) {
        getWarningsStream() << "You must specify " << cfgKey << ".size\n";
        return false;
    }

    cfg.start = s2e()->getConfig()->getInt(cfgKey + ".start", 0, &ok);
    if (!ok) {
        getWarningsStream() << "You must specify " << cfgKey << ".start\n";
        return false;
    }

    cfg.nativebase = s2e()->getConfig()->getInt(cfgKey + ".nativebase", 0, &ok);
    if (!ok) {
        getWarningsStream() << "You must specify " << cfgKey << ".nativebase\n";
        return false;
    }

    cfg.kernelMode = s2e()->getConfig()->getBool(cfgKey + ".kernelmode", false, &ok);
    if (!ok) {
        getWarningsStream() << "You must specify " << cfgKey << ".kernelmode\n";
        return false;
    }

    m_cfg.push_back(cfg);
    return true;
}

void RawMonitor::initialize() {
    m_vmi = s2e()->getPlugin<Vmi>();

    std::vector<std::string> Sections;
    Sections = s2e()->getConfig()->getListKeys(getConfigKey());
    bool noErrors = true;

    bool ok = false;
    m_kernelStart = s2e()->getConfig()->getInt(getConfigKey() + ".kernelStart", 0xc0000000, &ok);
    if (!ok) {
        getWarningsStream() << "You should specify " << getConfigKey() << ".kernelStart\n";
    }

    foreach2 (it, Sections.begin(), Sections.end()) {
        if (*it == "kernelStart") {
            continue;
        }

        getInfoStream() << "Scanning section " << getConfigKey() << "." << *it << '\n';
        std::stringstream sk;
        sk << getConfigKey() << "." << *it;
        if (!initSection(sk.str(), *it)) {
            noErrors = false;
        }
    }

    if (!noErrors) {
        getWarningsStream() << "Errors while scanning the RawMonitor sections\n";
        exit(-1);
    }

    m_stack.guest_stack_descriptor_ptr = 0;
    m_stack.stack_base = 0;
    m_stack.stack_size = 0;

    m_onTranslateInstruction = s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &RawMonitor::onTranslateInstructionStart));
}

/**********************************************************/
/**********************************************************/
/**********************************************************/

void RawMonitor::handleModuleLoad(S2EExecutionState *state, const S2E_RAWMON_COMMAND_MODULE_LOAD &m) {
    ModuleDescriptor module;
    std::string name, path;

    bool ret = true;

    ret &= state->mem()->readString(m.name, name);
    if (m.path) {
        ret &= state->mem()->readString(m.path, path);
    }

    if (!ret) {
        getWarningsStream(state) << "Could not read module name or path\n";
        return;
    }

    module.Name = name;
    module.Path = path;
    module.AddressSpace = state->regs()->getPageDir();
    module.Pid = m.pid;
    module.EntryPoint = m.entry_point;
    module.LoadBase = m.load_base;
    module.NativeBase = m.native_base;
    module.Size = m.size;

    if (m_vmi) {
        bool mp[2] = {true, false};
        for (int i = 0; i < 2; ++i) {
            auto exe = m_vmi->getFromDisk(module.Path, module.Name, mp[i]);
            if (exe) {
                module.NativeBase = exe->getImageBase();
                break;
            }
        }
    }

    getDebugStream(state) << module << "\n";

    onModuleLoad.emit(state, module);
}

void RawMonitor::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_RAWMON_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "RawMonitor: mismatched S2E_RAWMON_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "RawMonitor: could not read transmitted data\n";
        return;
    }

    completeInitialization(state);

    switch (command.Command) {
        case RAW_MODULE_LOAD: {
            handleModuleLoad(state, command.ModuleLoad);
        } break;

        case RAW_SET_CURRENT_STACK: {
            getDebugStream(state) << "RawMonitor: registering stack "
                                  << hexval(command.Stack.guest_stack_descriptor_ptr) << " "
                                  << hexval(command.Stack.stack_base) << " " << hexval(command.Stack.stack_size)
                                  << "\n";
            m_stack = command.Stack;
        } break;

        default: {
            getWarningsStream(state) << "RawMonitor: unknown command " << command.Command << "\n";
        } break;
    }
}

/**********************************************************/
/**********************************************************/
/**********************************************************/

void RawMonitor::loadModule(S2EExecutionState *state, const Cfg &c) {
    ModuleDescriptor md;

    md.Name = c.name;
    md.NativeBase = c.nativebase;
    md.LoadBase = c.start;
    md.Size = c.size;
    md.AddressSpace = c.kernelMode ? 0 : state->regs()->getPageDir();
    md.EntryPoint = c.entrypoint;

    getDebugStream() << "RawMonitor loaded " << c.name << " " << hexval(c.start) << ' ' << hexval(c.size) << '\n';
    onModuleLoad.emit(state, md);
}

void RawMonitor::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc) {
    CfgList::const_iterator it;

    for (it = m_cfg.begin(); it != m_cfg.end(); ++it) {
        const Cfg &c = *it;
        loadModule(state, c);
    }

    m_onTranslateInstruction.disconnect();
}

bool RawMonitor::getImports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Imports &I) {
    I = m_imports;
    return true;
}

bool RawMonitor::getExports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Exports &E) {
    return false;
}

bool RawMonitor::getRelocations(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Relocations &R) {
    return false;
}

bool RawMonitor::getCurrentStack(S2EExecutionState *state, uint64_t *base, uint64_t *size) {
    if (m_stack.stack_base && m_stack.stack_size) {
        *base = m_stack.stack_base;
        *size = m_stack.stack_size;
    } else if (m_stack.guest_stack_descriptor_ptr) {
        S2E_RAWMON_COMMAND_STACK stack;
        if (!state->mem()->read(m_stack.guest_stack_descriptor_ptr, &stack, sizeof(stack))) {
            return false;
        }
        *base = stack.stack_base;
        *size = stack.stack_size;
    } else {
        return false;
    }

    return true;
}
