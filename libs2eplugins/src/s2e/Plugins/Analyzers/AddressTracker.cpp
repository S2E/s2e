///
/// Copyright (C) 2020, Vitaly Chipounov
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
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2E.h>
#include <s2e/cpu.h>

#include <map>
#include <unordered_map>
#include <unordered_set>

#include "AddressTracker.h"

namespace s2e {
namespace plugins {

enum AddressTrackerTargetType { CodeTarget, ImmediateValue };

namespace {

class AddressTrackerState : public PluginState {
public:
    using UnorderedAddressMap = std::unordered_map<uint64_t, AddressTrackerTargetType>;
    using AddressMap = std::map<uint64_t, AddressTrackerTargetType>;

    struct AddressBundle {
        UnorderedAddressMap Unordered;
        AddressMap Ordered;
    };

    using AddressSpaces = std::unordered_map<uint64_t, AddressBundle>;

    AddressSpaces m_addresses;

    inline void add(uint64_t pid, const UnorderedAddressMap &addresses) {
        auto &bundle = m_addresses[pid];
        bundle.Ordered.insert(addresses.begin(), addresses.end());
        bundle.Unordered.insert(addresses.begin(), addresses.end());
    }

    inline void add(uint64_t pid, uint64_t address, AddressTrackerTargetType type) {
        auto &bundle = m_addresses[pid];
        bundle.Ordered[address] = type;
        bundle.Unordered[address] = type;
    }

    bool contains(uint64_t pid, uint64_t address) const {
        auto it = m_addresses.find(pid);
        if (it == m_addresses.end()) {
            return false;
        }

        return (*it).second.Unordered.count(address) > 0;
    }

    inline void remove(uint64_t pid, uint64_t start, uint64_t size) {
        auto ait = m_addresses.find(pid);
        if (ait == m_addresses.end()) {
            return;
        }

        auto &ordered = ait->second.Ordered;
        auto &unordered = ait->second.Unordered;

        auto sit = ordered.lower_bound(start);
        auto eit = ordered.upper_bound(start + size - 1);

        UnorderedAddressMap toErase(sit, eit);
        for (auto it : toErase) {
            unordered.erase(it.first);
        }

        ordered.erase(sit, eit);
    }

    inline void remove(uint64_t pid) {
        m_addresses.erase(pid);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new AddressTrackerState();
    }

    virtual ~AddressTrackerState() {
    }

    virtual AddressTrackerState *clone() const {
        return new AddressTrackerState(*this);
    }
};

} // namespace

S2E_DEFINE_PLUGIN(AddressTracker, "Describe what the plugin does here", "", "OSMonitor", "ModuleMap",
                  "ProcessExecutionDetector", "Vmi");

void AddressTracker::initialize() {
    m_modules = s2e()->getPlugin<ModuleMap>();
    m_process = s2e()->getPlugin<ProcessExecutionDetector>();
    m_vmi = s2e()->getPlugin<Vmi>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &AddressTracker::onModuleLoad));
    m_monitor->onModuleUnload.connect(sigc::mem_fun(*this, &AddressTracker::onModuleUnload));
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &AddressTracker::onProcessUnload));

    m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &AddressTracker::onMonitorLoad));
}

void AddressTracker::onMonitorLoad(S2EExecutionState *state) {
    s2e()->getCorePlugin()->onTranslateLeaRipRelative.connect(
        sigc::mem_fun(*this, &AddressTracker::onTranslateLeaRipRelative));

    s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
        sigc::mem_fun(*this, &AddressTracker::onTranslateSpecialInstructionEnd));

    // We have to start tracking addresses accurately, so flush the TB cache
    // so that we can see all the code.
    se_tb_safe_flush();
}

void AddressTracker::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    if (!m_process->isTrackedPid(state, module.Pid)) {
        return;
    }

    auto pd = m_vmi->getFromDisk(module.Path, module.Name, true);
    if (!pd) {
        getWarningsStream(state) << "cannot get PE file for " << module.Name << "\n";
        return;
    }

    DECLARE_PLUGINSTATE(AddressTrackerState, state);
    AddressTrackerState::UnorderedAddressMap addresses;

    uint64_t entryPoint;
    if (!module.ToRuntime(pd->getEntryPoint(), entryPoint)) {
        getWarningsStream(state) << "Could not get runtime address for entry point for module " << module.Name << "\n";
        return;
    }
    addresses[entryPoint] = AddressTrackerTargetType::CodeTarget;

    auto pe = std::dynamic_pointer_cast<vmi::PEFile>(pd);

    if (pe) {
        for (auto exception : pe->getExceptions()) {
            uint64_t addr;
            if (module.ToRuntime(exception, addr)) {
                addresses[addr] = CodeTarget;
            }
        }

        for (auto relocation : pe->getRelocations()) {
            uint64_t dst = relocation.second;
            uint64_t addr;
            if (module.ToRuntime(dst, addr)) {
                if (auto section = module.getSection(addr)) {
                    if (section->executable) {
                        addresses[addr] = CodeTarget;
                    }
                }
            }
        }

        auto ib = pe->getImageBase();
        for (auto exp : pe->getExports()) {
            uint64_t addr;
            if (module.ToRuntime(ib + exp.first, addr)) {
                addresses[addr] = CodeTarget;
            }
        }

        auto funcs = pe->guessFunctionAddresses();
        for (auto f : funcs) {
            uint64_t addr;
            if (module.ToRuntime(f, addr)) {
                addresses[addr] = CodeTarget;
            }
        }

        auto it = m_lea.find(module.Name);
        if (it != m_lea.end()) {
            for (auto naddr : (*it).second) {
                uint64_t addr;
                if (module.ToRuntime(naddr, addr)) {
                    addresses[addr] = CodeTarget;
                }
            }
        }
    }

    getDebugStream(state) << "Adding " << addresses.size() << " addresses for module " << module.Name << "\n";
    plgState->add(module.Pid, addresses);
}

void AddressTracker::onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module) {
    DECLARE_PLUGINSTATE(AddressTrackerState, state);

    for (const auto &section : module.Sections) {
        plgState->remove(module.Pid, section.runtimeLoadBase, section.size);
    }
}

void AddressTracker::onProcessUnload(S2EExecutionState *state, uint64_t cr3, uint64_t pid, uint64_t ReturnCode) {
    DECLARE_PLUGINSTATE(AddressTrackerState, state);
    plgState->remove(pid);
}

void AddressTracker::addTargetFromInstruction(S2EExecutionState *state, uint64_t pc, uint64_t addr, bool checkRange) {
    DECLARE_PLUGINSTATE(AddressTrackerState, state);

    for (auto pid : m_process->getTrackedPids(state)) {
        auto mod = m_modules->getModule(state, pid, pc);
        if (!mod) {
            continue;
        }

        if (checkRange && !mod->Contains(addr)) {
            continue;
        }

        plgState->add(pid, addr, ImmediateValue);
    }
}

void AddressTracker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                      TranslationBlock *tb, uint64_t pc,
                                                      enum special_instruction_t type,
                                                      const special_instruction_data_t *data) {
    if (type != PUSHIM) {
        return;
    }

    if (m_monitor->isKernelAddress(pc)) { // XXX make it configurable
        return;
    }

    // Ignore 16-bit mode
    if ((tb->flags >> VM_SHIFT) & 1) {
        return;
    }

    addTargetFromInstruction(state, pc, data->immediate_value, true);
}

void AddressTracker::onTranslateLeaRipRelative(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                               uint64_t pc, uint64_t addr) {
    if (m_monitor->isKernelAddress(pc)) { // XXX make it configurable
        return;
    }

    // Ignore 16-bit mode
    if ((tb->flags >> VM_SHIFT) & 1) {
        return;
    }

    // Collect the address for the current address space
    addTargetFromInstruction(state, pc, addr, false);

    auto mod = m_modules->getModule(state, addr);
    if (!mod) {
        return;
    }

    uint64_t native = 0;
    if (!mod->ToNativeBase(addr, native)) {
        return;
    }

    // We have to collect addresses across all address spaces
    // because binaries can be shared between processes.
    m_lea[mod->Name].insert(native);
}

bool AddressTracker::isValidCallTarget(S2EExecutionState *state, uint64_t pid, uint64_t address) const {
    DECLARE_PLUGINSTATE_CONST(AddressTrackerState, state);

    // TODO: distinguish call targets from anything else
    return plgState->contains(pid, address);
}

void AddressTracker::addCallTarget(S2EExecutionState *state, uint64_t pid, uint64_t pc) {
    DECLARE_PLUGINSTATE(AddressTrackerState, state);
    return plgState->add(pid, pc, CodeTarget);
}

} // namespace plugins
} // namespace s2e
