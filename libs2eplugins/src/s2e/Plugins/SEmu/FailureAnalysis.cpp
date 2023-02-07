///
/// Copyright (C) 2014-2015, Cyberhaven
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

#include <boost/regex.hpp>
#include <klee/util/ExprUtil.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include "FailureAnalysis.h"

#include <llvm/Support/CommandLine.h>

using namespace klee;

namespace s2e {
namespace plugins {
static const boost::regex SymbolicPeripheralRegEx("v\\d+_iommuread_(.+)_(.+)_(.+)", boost::regex::perl);

S2E_DEFINE_PLUGIN(FailureAnalysis, "Identify the failure reason of NLPModel", "");

namespace {
class FailureAnalysisState : public PluginState {
private:
    std::map<uint32_t, AllSymbolicPeripheralRegsMap> lastforkphs;

public:
    FailureAnalysisState() {
        lastforkphs.clear();
    }

    virtual ~FailureAnalysisState() {
    }

    static PluginState *factory(Plugin *, S2EExecutionState *) {
        return new FailureAnalysisState();
    }

    FailureAnalysisState *clone() const {
        return new FailureAnalysisState(*this);
    }
    // last fork phs
    void insertlastfork_phs(uint32_t irq_num, UniquePeripheral phc, uint64_t no, uint32_t value) {
        lastforkphs[irq_num][phc][no] = value;
    }

    AllSymbolicPeripheralRegsMap getlastfork_phs(uint32_t irq_num) {
        return lastforkphs[irq_num];
    }

    void clearlastfork_phs(uint32_t irq_num) {
        lastforkphs[irq_num].clear();
    }
};
} // namespace

void FailureAnalysis::initialize() {
    onInvalidStateDectionConnection = s2e()->getPlugin<InvalidStatesDetection>();
    onInvalidStateDectionConnection->onInvalidStatesEvent.connect(
        sigc::mem_fun(*this, &FailureAnalysis::onInvalidStatesDetection));
    s2e()->getCorePlugin()->onExceptionExit.connect(sigc::mem_fun(*this, &FailureAnalysis::onExceptionExit));
    s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &FailureAnalysis::onStateForkDecide));
    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &FailureAnalysis::onFork));
    s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &FailureAnalysis::onStateKill));
    s2e()->getCorePlugin()->onStateSwitch.connect(sigc::mem_fun(*this, &FailureAnalysis::onStateSwitch));
}

void SplitString(const std::string &s, std::vector<std::string> &v, const std::string &c) {
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while (std::string::npos != pos2) {
        v.push_back(s.substr(pos1, pos2 - pos1));

        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if (pos1 != s.length())
        v.push_back(s.substr(pos1));
}

bool FailureAnalysis::getPeripheralExecutionState(std::string variablePeripheralName, uint32_t *phaddr, uint32_t *pc,
                                                  uint32_t *size, uint64_t *no) {
    boost::smatch what;
    if (!boost::regex_match(variablePeripheralName, what, SymbolicPeripheralRegEx)) {
        getWarningsStream() << "match false\n";
        exit(0);
        return false;
    }

    if (what.size() != 4) {
        getWarningsStream() << "wrong size = " << what.size() << "\n";
        exit(0);
        return false;
    }

    std::string peripheralAddressStr = what[1];
    std::string sizeStr = what[2];
    std::string noStr = what[3];

    std::vector<std::string> v;
    SplitString(peripheralAddressStr, v, "_");
    *phaddr = std::stoull(v[0].c_str(), NULL, 16);
    *pc = std::stoull(v[1].c_str(), NULL, 16);
    *size = std::stoull(sizeStr.c_str(), NULL, 16);
    *no = std::stoull(noStr.c_str(), NULL, 10);

    return true;
}

void FailureAnalysis::onExceptionExit(S2EExecutionState *state, uint32_t irq_no) {
    DECLARE_PLUGINSTATE(FailureAnalysisState, state);
    getDebugStream(state) << "Interrupt exit irq num = " << hexval(irq_no) << "\n";
    plgState->clearlastfork_phs(irq_no);
}

void FailureAnalysis::onStateForkDecide(S2EExecutionState *state, bool *doFork, const klee::ref<klee::Expr> &condition,
                                        bool *conditionFork) {
    uint32_t curPc = state->regs()->getPc();
    getDebugStream(state) << "Fork Decitde pc = " << hexval(curPc) << "\n";
    *conditionFork = false;
}

void FailureAnalysis::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                             const std::vector<klee::ref<klee::Expr>> &newConditions) {
    std::map<uint32_t, AllSymbolicPeripheralRegsMap> cachefork_phs;
    cachefork_phs.clear();
    bool check = false;
    for (int k = newStates.size() - 1; k >= 0; --k) {
        ArrayVec results;

        findSymbolicObjects(newConditions[0], results);
        for (int i = results.size() - 1; i >= 0; --i) { // one cond multiple sym var
            uint32_t phaddr;
            uint32_t pc;
            uint32_t size;
            uint64_t no;
            auto &arr = results[i];
            std::vector<unsigned char> data;

            getPeripheralExecutionState(arr->getName(), &phaddr, &pc, &size, &no);
            onForkCheck.emit(state, phaddr, check);
            check = true;
            // getDebugStream() << "The symbol name of value is " << arr->getName() << "\n";
            for (unsigned s = 0; s < arr->getSize(); ++s) {
                ref<Expr> e = newStates[k]->concolics->evaluate(arr, s);
                if (!isa<ConstantExpr>(e)) {
                    getWarningsStream() << "Failed to evaluate concrete value\n";
                    pabort("Failed to evaluate concrete value");
                }

                uint8_t val = dyn_cast<ConstantExpr>(e)->getZExtValue();
                data.push_back(val);
            }

            uint32_t condConcreteValue =
                data[0] | ((uint32_t) data[1] << 8) | ((uint32_t) data[2] << 16) | ((uint32_t) data[3] << 24);

            UniquePeripheral uniquePeripheral = std::make_pair(phaddr, pc);
            uint64_t LSB = ((uint64_t) 1 << (size * 8));
            uint32_t value = condConcreteValue & (LSB - 1);

            cachefork_phs[k][uniquePeripheral][no] = value;
            getInfoStream(newStates[k]) << " path: phaddr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                        << " value = " << hexval(value) << " no = " << no << "\n";

        } // each condition

        // push fork states in interrupt
        if (newStates[k]->regs()->getInterruptFlag()) {
            if (newStates[k] != state) {
                getDebugStream() << "push irq state" << newStates[k]->getID() << "\n";
                irq_states.push_back(newStates[k]);
            }
        }

    } // each new State

    for (int k = newStates.size() - 1; k >= 0; --k) {
        DECLARE_PLUGINSTATE(FailureAnalysisState, newStates[k]);
        // only update kb for new condition
        if (newStates[k]->regs()->getInterruptFlag()) {
            plgState->clearlastfork_phs(newStates[k]->regs()->getExceptionIndex());
            for (auto &it : cachefork_phs[k]) {
                for (auto &itch : it.second) {
                    plgState->insertlastfork_phs(newStates[k]->regs()->getExceptionIndex(), it.first, itch.first,
                                                 itch.second);
                }
            }
        } else {
            plgState->clearlastfork_phs(0);
            for (auto &it : cachefork_phs[k]) {
                for (auto &itch : it.second) {
                    plgState->insertlastfork_phs(0, it.first, itch.first, itch.second);
                }
            }
        }
    }
}

void FailureAnalysis::onInvalidStatesDetection(S2EExecutionState *state, uint32_t pc, InvalidStatesType type,
                                               uint64_t tb_num) {
    // remove current state in cache interrupt states
    if (irq_states.size() > 0) {
        auto itirqs = irq_states.begin();
        for (; itirqs != irq_states.end();) {
            if (*itirqs == state) {
                getDebugStream() << "delete currecnt state in irq states " << (*itirqs)->getID() << "\n";
                irq_states.erase(itirqs);
            } else {
                itirqs++;
            }
        }
    }

    // push all useless irq states together and kill.
    if (!state->regs()->getInterruptFlag()) {
        for (auto firqs : irq_states) {
            if (find(false_type_phs_fork_states.begin(), false_type_phs_fork_states.end(), firqs) ==
                false_type_phs_fork_states.end()) {
                getDebugStream() << "Kill Fork State in interrupt:" << firqs->getID() << "\n";
                false_type_phs_fork_states.push_back(firqs);
            }
        }
        fs = -1;
        irq_states.clear();
    }
}

void FailureAnalysis::onStateKill(S2EExecutionState *state) {
    if (irq_states.size() > 0) {
        auto itirqs = irq_states.begin();
        for (; itirqs != irq_states.end();) {
            if (*itirqs == state) {
                irq_states.erase(itirqs);
            } else {
                itirqs++;
            }
        }
    }

    fs++;
    while (fs < false_type_phs_fork_states.size()) {
        std::string s;
        llvm::raw_string_ostream ss(s);
        ss << "Kill Fork State in false status phs:" << false_type_phs_fork_states[fs]->getID() << "\n";
        ss.flush();
        s2e()->getExecutor()->terminateState(*false_type_phs_fork_states[fs], s);
    }
    fs = -1;
    false_type_phs_fork_states.clear();
}

std::vector<uint32_t> identify_setbit_loc(uint32_t value) {
    std::vector<uint32_t> setbit_loc_vec;
    std::vector<bool> bin_vec;
    for (int j = value; j; j = j / 2) {
        bin_vec.push_back(j % 2 ? 1 : 0);
    }

    for (int k = 0; k < bin_vec.size(); k++) {
        if (bin_vec[k] == 1) {
            setbit_loc_vec.push_back(k);
        }
    }

    return setbit_loc_vec;
}

void FailureAnalysis::onStateSwitch(S2EExecutionState *currentState, S2EExecutionState *nextState) {
    getDebugStream() << "next irq flag = " << nextState->regs()->getInterruptFlag()
                     << " previous irq flag = " << currentState->regs()->getInterruptFlag() << "\n";

    AllSymbolicPeripheralRegsMap wrong_last_fork_phs, correct_last_fork_phs;
    if (!nextState->regs()->getInterruptFlag() && !currentState->regs()->getInterruptFlag()) {
        wrong_last_fork_phs = getLastBranchTargetRegValues(currentState, 0);
        correct_last_fork_phs = getLastBranchTargetRegValues(nextState, 0);
    } else if (nextState->regs()->getInterruptFlag() && currentState->regs()->getInterruptFlag() &&
               (currentState->regs()->getExceptionIndex() == nextState->regs()->getExceptionIndex())) {
        wrong_last_fork_phs = getLastBranchTargetRegValues(currentState, currentState->regs()->getExceptionIndex());
        correct_last_fork_phs = getLastBranchTargetRegValues(nextState, nextState->regs()->getExceptionIndex());
    } else {
        getWarningsStream() << "Error!!!\n";
    }

    getWarningsStream() << "=========== Unit test Failed! ==========\n";
    for (auto wrong_last_fork_ph : wrong_last_fork_phs) {
        for (auto ph : wrong_last_fork_ph.second) {
            // uint32_t correct_bits = ! (ph.second ^ correct_last_fork_phs[wrong_last_fork_ph.first][ph.first]);
            uint32_t wrong_bits = correct_last_fork_phs[wrong_last_fork_ph.first][ph.first] ^ ph.second;
            getWarningsStream() << "Wrong Peripheral = " << hexval(wrong_last_fork_ph.first.first)
                                << " at pc = " << hexval(wrong_last_fork_ph.first.second)
                                << " wrong value = " << hexval(ph.second) << " correct value = "
                                << hexval(correct_last_fork_phs[wrong_last_fork_ph.first][ph.first]) << "\n";
            std::string wrongbitStr = "Wrong bit:";
            for (auto bit_loc : identify_setbit_loc(wrong_bits)) {
                wrongbitStr += " " + std::to_string(bit_loc);
            }
            getWarningsStream() << wrongbitStr << "\n";
        }
    }
    exit(-1);
    // based on wrong state to identify
}

AllSymbolicPeripheralRegsMap FailureAnalysis::getLastBranchTargetRegValues(S2EExecutionState *state, uint32_t irq_num) {
    DECLARE_PLUGINSTATE(FailureAnalysisState, state);

    return plgState->getlastfork_phs(irq_num);
}

} // namespace plugins
} // namespace s2e
