///
/// Copyright (C) 2015-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include "ARMFunctionMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ARMFunctionMonitor, "Function monitoring plugin", "ARMFunctionMonitor");

namespace {
class ARMFunctionMonitorState : public PluginState {
private:
    std::vector<uint32_t> call_stack;

public:
    ARMFunctionMonitorState() {
    }
    virtual ~ARMFunctionMonitorState() {
    }
    virtual ARMFunctionMonitorState *clone() const {
        return new ARMFunctionMonitorState(*this);
    }
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new ARMFunctionMonitorState();
    }

    void push_currect_callerpc(uint32_t pc) {
        call_stack.push_back(pc);
    }

    void pop_current_callstack() {
        call_stack.pop_back();
    }

    uint32_t get_current_callerpc() {
        return call_stack.back();
    }

    std::vector<uint32_t> get_call_stack() {
        return call_stack;
    }

    /*void update_functionmap(uint32_t calleraddress, uint32_t return_address) {*/
    // functionmap[calleraddress] = return_address;
    //}

    // std::map<uint32_t, uint32_t> get_functionmap() {
    // return functionmap;
    /*}*/
};
}

template <typename T> static bool getConcolicValue(S2EExecutionState *state, unsigned offset, T *value) {
    auto size = sizeof(T);

    klee::ref<klee::Expr> expr = state->regs()->read(offset, size * 8);
    if (isa<klee::ConstantExpr>(expr)) {
        klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(expr);
        *value = ce->getZExtValue();
        return true;
    }

    // evaluate symobolic regs
    klee::ref<klee::ConstantExpr> ce;
    ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(expr));
    *value = ce->getZExtValue();
    return false;
}

uint64_t FNV1aHash(std::vector<uint64_t> data) {
    const uint64_t fnv_prime = 0xcbf29ce484222325;
    uint64_t data_hash = 0x100000001b3;

    for (unsigned i = 0; i < data.size(); i++) {
        data_hash ^= data[i];
        data_hash *= fnv_prime;
    }

    return data_hash;
}

uint64_t FNV1Hash(std::vector<uint32_t> data) {
    const uint64_t fnv_prime = 0xcbf29ce484222325;
    uint64_t data_hash = 0x100000001b3;

    for (unsigned i = 0; i < data.size(); i++) {
        data_hash *= fnv_prime;
        data_hash ^= data[i];
    }

    return data_hash;
}

uint64_t getRegsHash(S2EExecutionState *state, uint32_t para_num) {
    std::vector<uint32_t> conregs;

    for (unsigned i = 0; i < para_num; ++i) {
        unsigned offset = offsetof(CPUARMState, regs[i]);
        target_ulong concreteData;

        if (state->regs()->read(offset, &concreteData, sizeof(concreteData), false)) {
            getConcolicValue(state, offset, &concreteData);
            conregs.push_back(concreteData);
        }
        // g_s2e->getDebugStream() << "reg " << i << " = " << hexval(concreteData) << "\n";
    }

    return FNV1Hash(conregs);
}

void ARMFunctionMonitor::initialize() {

    bool ok;
    function_parameter_num = s2e()->getConfig()->getInt(getConfigKey() + ".functionParameterNum", 3, &ok);
    caller_level = s2e()->getConfig()->getInt(getConfigKey() + ".callerLevel", 3, &ok);

    if (!ok || function_parameter_num > 4 || caller_level > 5) {
        getWarningsStream()
            << "Currently, we only support at most four function parameters and five level caller levels for t2 type\n";
        exit(-1);
    } else {
        getDebugStream() << "function parameters number is " << function_parameter_num
                         << " caller_level = " << caller_level << "\n";
    }

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &ARMFunctionMonitor::onTranslateBlockStart));
    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &ARMFunctionMonitor::onTranslateBlockEnd));
}

void ARMFunctionMonitor::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                               uint64_t pc) {
    signal->connect(sigc::mem_fun(*this, &ARMFunctionMonitor::onFunctionReturn));
}

void ARMFunctionMonitor::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc, bool isStatic, uint64_t staticTarget) {
    if (tb->se_tb_type == TB_CALL || tb->se_tb_type == TB_CALL_IND) {
        signal->connect(
            sigc::bind(sigc::mem_fun(*this, &ARMFunctionMonitor::onFunctionCall), (unsigned) tb->se_tb_type));
    }
}

void ARMFunctionMonitor::onFunctionCall(S2EExecutionState *state, uint64_t caller_pc, unsigned source_type) {
    DECLARE_PLUGINSTATE(ARMFunctionMonitorState, state);

    uint64_t regs_hash = getRegsHash(state, function_parameter_num);
    std::vector<uint64_t> sum_hash_vec;
    sum_hash_vec.push_back(regs_hash);

    std::vector<uint32_t> call_stack = plgState->get_call_stack();
    std::vector<uint32_t> caller_pc_hash_vec;
    caller_pc_hash_vec.push_back(caller_pc);
    if (call_stack.size() > caller_level - 1) {
        for (int i = 0; i < caller_level - 2; i++) {
            caller_pc_hash_vec.push_back(call_stack[call_stack.size() - 1 - i]);
        }
    }
    uint64_t caller_pc_hash = FNV1Hash(caller_pc_hash_vec);
    sum_hash_vec.push_back(caller_pc_hash);
    uint64_t sum_hash = FNV1aHash(sum_hash_vec);

    uint32_t return_address;
    uint32_t lr = state->regs()->getLr();
    if (source_type == TB_CALL) {
        return_address = caller_pc + 4;
        getDebugStream() << "direct call lr = " << hexval(lr) << "\n";
    } else if (source_type == TB_CALL_IND) {
        return_address = caller_pc + 2;
        getDebugStream() << "indirect call lr = " << hexval(lr) << "\n";
    } else {
        getWarningsStream() << "should not be here!!!\n";
        return;
    }
    getDebugStream() << "caller pc = " << hexval(caller_pc) << " hash = " << hexval(sum_hash)
                     << " return address = " << hexval(return_address) << "\n";
    plgState->push_currect_callerpc(caller_pc);
    if (function_map.find(caller_pc) == function_map.end()) {
        function_map[caller_pc] = return_address;
    }
    onARMFunctionCallEvent.emit(state, caller_pc, sum_hash);
}

void ARMFunctionMonitor::onFunctionReturn(S2EExecutionState *state, uint64_t return_pc) {
    DECLARE_PLUGINSTATE(ARMFunctionMonitorState, state);
    std::vector<uint32_t> call_stack = plgState->get_call_stack();
    if (call_stack.size() == 0) {
        return;
    }
    uint32_t last_callerpc = plgState->get_current_callerpc();
    if (function_map.find(last_callerpc) != function_map.end()) {
        if (function_map[last_callerpc] == return_pc) {
            plgState->pop_current_callstack();
            onARMFunctionReturnEvent.emit(state, return_pc);
            getDebugStream() << "last caller_pc = " << hexval(last_callerpc) << " return pc = " << hexval(return_pc)
                             << "\n";
        }
    } else {
        getWarningsStream() << "invalid last caller pc = " << hexval(last_callerpc) << "\n";
    }
}

} // namespace plugins
} // namespace s2e
