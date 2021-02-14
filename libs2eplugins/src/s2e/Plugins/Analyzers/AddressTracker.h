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

#ifndef S2E_PLUGINS_ADDRESSTRACKER_H
#define S2E_PLUGINS_ADDRESSTRACKER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>

namespace s2e {
struct ModuleDescriptor;

namespace plugins {

class ModuleMap;
class OSMonitor;
class ProcessExecutionDetector;
class Vmi;

///
/// \brief The AddressTracker plugin tracks code targets in processes.
///
/// This plugins manages a set of addresses that can be potentially be
/// targets of indirect calls, jumps, etc. This can be useful for applications
/// such as control flow integrity checking.
///
class AddressTracker : public Plugin {
    S2E_PLUGIN

    OSMonitor *m_monitor;
    ModuleMap *m_modules;
    ProcessExecutionDetector *m_process;
    Vmi *m_vmi;

    using AddressSet = std::unordered_set<uint64_t>;
    using BinaryNameToAddresses = std::unordered_map<std::string, AddressSet>;

    BinaryNameToAddresses m_lea;

public:
    AddressTracker(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    bool isValidCallTarget(S2EExecutionState *state, uint64_t pid, uint64_t address) const;
    void addCallTarget(S2EExecutionState *state, uint64_t pid, uint64_t pc);

private:
    void onMonitorLoad(S2EExecutionState *state);

    void onTranslateLeaRipRelative(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                                   uint64_t addr);

    void onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                          uint64_t pc, enum special_instruction_t type,
                                          const special_instruction_data_t *data);

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module);
    void onProcessUnload(S2EExecutionState *state, uint64_t cr3, uint64_t pid, uint64_t ReturnCode);

    void addTargetFromInstruction(S2EExecutionState *state, uint64_t pc, uint64_t addr, bool checkRange);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ADDRESSTRACKER_H
