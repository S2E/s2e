///
/// Copyright (C) 2014, Cyberhaven
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

#ifndef S2E_PLUGINS_FailureAnalysis_H
#define S2E_PLUGINS_FailureAnalysis_H

#include <deque>
#include <inttypes.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/SEmu/InvalidStatesDetection.h>
#include <s2e/S2EExecutionState.h>
#include <vector>

#include <llvm/ADT/SmallVector.h>

namespace s2e {
namespace plugins {

typedef std::pair<uint32_t /* peripheraladdress */, uint32_t /* pc */> UniquePeripheral;
typedef std::map<uint64_t /* unique no */, uint32_t /* value */> NoMap;
typedef std::map<UniquePeripheral, NoMap> AllSymbolicPeripheralRegsMap;
class FailureAnalysis : public Plugin {
    S2E_PLUGIN
public:
    FailureAnalysis(S2E *s2e) : Plugin(s2e) {
    }

    sigc::signal<void, S2EExecutionState *, uint32_t, bool> onForkCheck;

    void initialize();
    void onExceptionExit(S2EExecutionState *state, uint32_t irq_no);
    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);
    void onStateKill(S2EExecutionState *state);
    void onStateSwitch(S2EExecutionState *current, S2EExecutionState *next);
    void onStateForkDecide(S2EExecutionState *state, bool *doFork, const klee::ref<klee::Expr> &condition,
                           bool *conditionFork);
    void onInvalidStatesDetection(S2EExecutionState *state, uint32_t pc, InvalidStatesType type, uint64_t tb_num);

private:
    InvalidStatesDetection *onInvalidStateDectionConnection;
    std::vector<S2EExecutionState *> irq_states; // forking states in interrupt
    int fs;                                      // count for false status fork states kill;
    std::vector<S2EExecutionState *> false_type_phs_fork_states;

    AllSymbolicPeripheralRegsMap getLastBranchTargetRegValues(S2EExecutionState *state, uint32_t irq_num);
    bool getPeripheralExecutionState(std::string variablePeripheralName, uint32_t *phaddr, uint32_t *size, uint32_t *pc,
                                     uint64_t *no);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FailureAnalysis_H
