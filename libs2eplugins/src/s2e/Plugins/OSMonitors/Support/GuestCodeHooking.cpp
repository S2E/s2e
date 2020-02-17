///
/// Copyright (C) 2018 Cyberhaven
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
#include <s2e/opcodes.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "GuestCodeHooking.h"

namespace std {
template <> struct hash<s2e::plugins::os::HookLocation> {
    std::size_t operator()(const s2e::plugins::os::HookLocation &k) const {
        return k.pc ^ k.pid;
    }
};
} // namespace std

namespace s2e {
namespace plugins {
namespace os {

S2E_DEFINE_PLUGIN(GuestCodeHooking, "GuestCodeHooking S2E plugin", "", "ModuleMap", "Vmi", "OSMonitor");

namespace {

typedef std::unordered_map<HookLocation, Hook> Hooks;

class GuestCodeHookingState : public PluginState {
public:
    // These hooks will be called always, regardless of the caller.
    // The instrumentation is inserted at the start of the translation block.
    Hooks m_functionHooks;

    // The hooks will be called at the call site of modules of interest.
    // The instrumention is inserted at the call site.
    Hooks m_callSiteHooks;

    GuestCodeHookingState() {
    }
    virtual ~GuestCodeHookingState() {
    }
    virtual GuestCodeHookingState *clone() const {
        return new GuestCodeHookingState(*this);
    }
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new GuestCodeHookingState();
    }
};
} // namespace

void GuestCodeHooking::initialize() {
    m_map = s2e()->getPlugin<ModuleMap>();
    m_vmi = s2e()->getPlugin<Vmi>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list mods = cfg->getStringList(getConfigKey() + ".moduleNames");
    if (mods.size() == 0) {
        getWarningsStream() << "You should specify modules to hook in moduleNames" << '\n';
    }

    for (const auto &mod : mods) {
        m_modules.insert(mod);
    }

    m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &GuestCodeHooking::onModuleLoad));
    m_monitor->onModuleUnload.connect(sigc::mem_fun(*this, &GuestCodeHooking::onModuleUnload));
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &GuestCodeHooking::onProcessUnload));

    // For unconditional function hooking
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &GuestCodeHooking::onTranslateBlockStart));

    // For call site hooking
    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &GuestCodeHooking::onTranslateBlockEnd));
}

void GuestCodeHooking::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {

    // TODO: may be better to identify modules by path instead,
    // in order to avoid collisions.
    if (m_modules.count(module.Name) == 0) {
        return;
    }

    if (m_availableFcnHooks.size() == 0) {
        return;
    }

    vmi::Imports imports;
    if (!m_vmi->getResolvedImports(state, module, imports)) {
        getWarningsStream(state) << "could not load imports for " << module << "\n";
        return;
    }

    for (const auto &importedModule : imports) {
        const auto &impModName = importedModule.first;
        const auto &impSymbols = importedModule.second;

        const auto &availableFcnHooksIt = m_availableFcnHooks.find(impModName);
        if (availableFcnHooksIt == m_availableFcnHooks.end()) {
            continue;
        }

        if ((*availableFcnHooksIt).second.empty()) {
            continue;
        }

        DECLARE_PLUGINSTATE(GuestCodeHookingState, state);

        // For every available hook for the given module,
        // scan the import table of the module and resolve function name
        // to actual pc.
        for (const auto &fcnHook : (*availableFcnHooksIt).second) {
            if (fcnHook.Pid != module.Pid) {
                continue;
            }

            // Get the function to hook
            const auto fit = impSymbols.find(fcnHook.FunctionName);
            if (fit == impSymbols.end()) {
                continue;
            }

            const vmi::ImportedSymbol &sym = (*fit).second;
            HookLocation loc;
            loc.pc = sym.address;
            loc.pid = module.Pid;

            Hook hook;
            hook.target_pc = fcnHook.HookPc;
            hook.hook_return_64 = fcnHook.HookReturn64;

            plgState->m_callSiteHooks[loc] = hook;
        }
    }
}

void GuestCodeHooking::erase(S2EExecutionState *state, GuestCodeHooking::GCHPredicate doErase) {
    DECLARE_PLUGINSTATE(GuestCodeHookingState, state);
    bool needFlush = false;
    auto eraser = [&](Hooks &hooks) {
        std::vector<HookLocation> toErase;
        for (const auto it : hooks) {
            if (doErase(it.first, it.second)) {
                toErase.push_back(it.first);
                needFlush = true;
            }
        }
        for (const auto it : toErase) {
            hooks.erase(it);
        }
    };

    eraser(plgState->m_functionHooks);
    eraser(plgState->m_callSiteHooks);

    if (needFlush) {
        // Avoid calling stale instrumentation
        se_tb_safe_flush();
    }
}

void GuestCodeHooking::onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module) {
    auto doErase = [&](const HookLocation &loc, const Hook &hpc) {
        return (module.Pid == loc.pid) && (module.Contains(loc.pc) || module.Contains(hpc.target_pc));
    };

    erase(state, doErase);
}

void GuestCodeHooking::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode) {
    auto doErase = [=](const HookLocation &loc, const Hook &hpc) { return pid == loc.pid; };
    erase(state, doErase);
}

// This is used for two types of hooks:
// - Library function hooks that must be called regardless of the caller
// - Entry point hooks (e.g., kernel calls a specific driver)
void GuestCodeHooking::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc) {
    if (!m_monitor->initialized()) {
        return;
    }

    DECLARE_PLUGINSTATE(GuestCodeHookingState, state);
    auto pid = m_monitor->getPid(state);
    pid = m_monitor->translatePid(pid, pc);

    HookLocation loc;
    loc.pc = pc;
    loc.pid = pid;

    const auto it = plgState->m_functionHooks.find(loc);
    if (it == plgState->m_functionHooks.end()) {
        return;
    }

    const Hook &hook = (*it).second;

    signal->connect(sigc::bind(sigc::mem_fun(*this, &GuestCodeHooking::onExecuteBlockStart), hook.target_pc, true),
                    fsigc::signal_base::HIGH_PRIORITY);
}

void GuestCodeHooking::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc, uint64_t hookAddress,
                                           bool directHook) {
    // Get the caller
    uint64_t ra;
    if (!state->getReturnAddress(&ra)) {
        getDebugStream(state) << "could not determine return address\n";
        return;
    }

    auto module = m_map->getModule(state, ra);
    if (!module) {
        return;
    }

    // Prevent infinite recursion.
    if (module->Name.find("s2e.sys") != std::string::npos) {
        return;
    }

    if (directHook) {
        state->regs()->setPc(hookAddress);
        throw CpuExitException();
    } else {
        // TODO: implement entry point hooks
    }
}

void GuestCodeHooking::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                           uint64_t pc, bool staticTarget, uint64_t targetPc) {
    if (!m_monitor->initialized()) {
        return;
    }

    if (tb->se_tb_type != TB_CALL_IND && tb->se_tb_type != TB_CALL) {
        return;
    }

    auto module = m_map->getModule(state);
    if (!module) {
        return;
    }

    // The module we are currently translating is not one we are interested in
    if (m_modules.count(module->Name) == 0) {
        return;
    }

    signal->connect(sigc::mem_fun(*this, &GuestCodeHooking::onExecuteCall));
}

void GuestCodeHooking::onExecuteCall(S2EExecutionState *state, uint64_t pc) {
    HookLocation callee;
    callee.pc = state->regs()->getPc();
    callee.pid = m_monitor->translatePid(m_monitor->getPid(state), callee.pc);

    DECLARE_PLUGINSTATE(GuestCodeHookingState, state);
    const auto it = plgState->m_callSiteHooks.find(callee);
    if (it == plgState->m_callSiteHooks.end()) {
        return;
    }

    const Hook &hook = (*it).second;

    state->regs()->setPc(hook.target_pc);
    throw CpuExitException();
}

bool GuestCodeHooking::parseGHLFcn(S2EExecutionState *state, const S2E_GUEST_HOOK_LIBRARY_FCN &in,
                                   S2E_GUEST_HOOK_LIBRARY_FCN_CPP &out) {
    out.HookPc = in.HookPc;
    out.Pid = m_monitor->translatePid(in.Pid, in.HookPc);
    out.HookReturn64 = in.HookReturn64;

    bool ok = true;
    ok &= state->mem()->readString(in.LibraryName, out.LibraryName);
    ok &= state->mem()->readString(in.FunctionName, out.FunctionName);
    if (!ok) {
        getWarningsStream(state) << "Could not parse S2E_GUEST_HOOK_LIBRARY_FCN structure\n";
    }
    return ok;
}

void GuestCodeHooking::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_GUEST_HOOK_PLUGIN_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_GUEST_HOOK_PLUGIN_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    DECLARE_PLUGINSTATE(GuestCodeHookingState, state);

    switch (command.Command) {
        case REGISTER_DIRECT_HOOK: {
            HookLocation loc;
            loc.pc = command.DirectHook.OriginalPc;
            loc.pid = m_monitor->translatePid(command.DirectHook.Pid, loc.pc);

            Hook hook;
            hook.hook_return_64 = 0;
            hook.target_pc = command.DirectHook.HookPc;

            plgState->m_functionHooks[loc] = hook;

            getInfoStream(state) << "Registered function hook at " << hexval(loc.pid) << ":" << hexval(loc.pc) << " to "
                                 << hexval(hook.target_pc) << "\n";

            se_tb_safe_flush();
        } break;

        case UNREGISTER_DIRECT_HOOK: {
            HookLocation loc;
            loc.pc = command.DirectHook.OriginalPc;
            loc.pid = m_monitor->translatePid(command.DirectHook.Pid, loc.pc);
            plgState->m_functionHooks.erase(loc);

            getInfoStream(state) << "Unregistered function hook at " << hexval(loc.pid) << ":" << hexval(loc.pc)
                                 << "\n";

            se_tb_safe_flush();
        } break;

        case REGISTER_CALL_SITE_HOOK: {
            const auto &csh = command.CallSiteHook;
            S2E_GUEST_HOOK_LIBRARY_FCN_CPP cshcpp;

            if (parseGHLFcn(state, csh, cshcpp)) {
                if (m_availableFcnHooks[cshcpp.LibraryName].count(cshcpp)) {
                    getWarningsStream(state) << "already contains hook for pid " << hexval(cshcpp.Pid) << " "
                                             << cshcpp.LibraryName << ":" << cshcpp.FunctionName << "\n";
                } else {
                    m_availableFcnHooks[cshcpp.LibraryName].insert(cshcpp);
                    getInfoStream(state) << "Registered call site hook for pid " << hexval(cshcpp.Pid) << " at "
                                         << cshcpp.LibraryName << ":" << cshcpp.FunctionName << " to "
                                         << hexval(cshcpp.HookPc) << "\n";
                }
                se_tb_safe_flush();
            }
        } break;

        case UNREGISTER_CALL_SITE_HOOK: {
            const auto &csh = command.CallSiteHook;
            S2E_GUEST_HOOK_LIBRARY_FCN_CPP cshcpp;
            if (parseGHLFcn(state, csh, cshcpp)) {
                if (!m_availableFcnHooks[cshcpp.LibraryName].erase(cshcpp)) {
                    getWarningsStream(state) << "could not erase hook for pid " << hexval(cshcpp.Pid) << " "
                                             << cshcpp.LibraryName << ":" << cshcpp.FunctionName << "\n";
                }
            }
        } break;
    }
}

} // namespace os
} // namespace plugins
} // namespace s2e
