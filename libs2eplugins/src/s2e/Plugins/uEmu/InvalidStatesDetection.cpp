///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include <iostream>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "InvalidStatesDetection.h"

#include <llvm/Support/CommandLine.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InvalidStatesDetection, "Kill dead loops of executed translation blocks", "InvalidStatesDetection");

namespace {

class InvalidStatesDetectionState : public PluginState {
private:
    CacheConregs cacheconregs;
    CacheConregs loopconregs;
    // add count limit
    std::map<UniquePcRegMap, uint32_t /* count */> reg_loop_count;
    std::map<UniquePcRegMap, std::deque<int> /* reg_value */> re_reg_map;
    std::map<uint32_t, uint32_t /* count */> kill_point_count;
    uint32_t max_cache_tb_num; // total tb number in cache
    uint64_t max_loop_limit;
    bool loopcmpflag;
    bool modeflag;       // only kill in symbolic mode
    uint64_t new_tb_num; // new tb number in per state
    uint64_t re_tb_num;  // repeat tb number in per state
    uint64_t tb_num;     // all tb number in per state
    bool enable_kill;    // indicate all external irqs have been invoked at once;
    TBCounts new_tb_map;
    uint32_t current_irq_num;

public:
    virtual InvalidStatesDetectionState *clone() const {
        return new InvalidStatesDetectionState(*this);
    }

    InvalidStatesDetectionState() {
        tb_num = 0;
        new_tb_num = 0;
        re_tb_num = 0;
        loopcmpflag = false;
        enable_kill = false;
        cacheconregs.clear();
        loopconregs.clear();
        new_tb_map.clear();
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new InvalidStatesDetectionState();
    }

    virtual ~InvalidStatesDetectionState() {
    }

    void reset_allcache() {
        tb_num = 0;
        re_tb_num = 0;
        loopcmpflag = false;
        enable_kill = false;
        cacheconregs.clear();
        loopconregs.clear();
    }

    void inckpcount(uint32_t pc) {
        kill_point_count[pc]++;
    }

    uint32_t getkpcount(uint32_t pc) {
        return kill_point_count[pc];
    }

    // long loop judgement
    void setmaxloopnum(uint64_t max_loop_tb_num) {
        max_loop_limit = max_loop_tb_num;
    }

    bool judgelongloopregs(UniquePcRegMap uniquepcregmap, uint32_t reg_value) {
        re_reg_map[uniquepcregmap].push_back(reg_value);
        if (re_reg_map[uniquepcregmap].size() > 2) {
            if (std::abs(re_reg_map[uniquepcregmap][2] - re_reg_map[uniquepcregmap][1]) == 1) {
                reg_loop_count[uniquepcregmap]++;
                if (reg_loop_count[uniquepcregmap] > (max_loop_limit - 5)) {
                    reg_loop_count[uniquepcregmap] = 0;
                    return true;
                }
            } else {
                // printf("re_reg_map[uniquepcregmap][2] = 0x%x, re_reg_map[uniquepcregmap][1] = 0x%x\n",
                // re_reg_map[uniquepcregmap][2], re_reg_map[uniquepcregmap][1]);
                reg_loop_count[uniquepcregmap] = 0;
            }
            re_reg_map[uniquepcregmap].pop_front();
        }
        return false;
    }

    void setenablekill(bool enablekill) {
        enable_kill = enablekill;
    }

    bool getenablekill() {
        return enable_kill;
    }

    void assignloopregs(uint32_t i) {
        // already judge first one continue will the second
        loopconregs.assign(cacheconregs.begin() + i, cacheconregs.end());
    }

    ConRegs getcurloopregs() {
        return loopconregs.at(0);
    }

    void poploopregs() {
        loopconregs.pop_front();
    }

    uint32_t getloopsize() {
        return loopconregs.size();
    }

    void setloopflag(bool loop_cmp_flag) {
        loopcmpflag = loop_cmp_flag;
    }

    bool getloopflag() {
        return loopcmpflag;
    }
    /// concrete mode judgement
    void setmodeflag(bool mode_flag) {
        modeflag = mode_flag;
    }

    bool getmodeflag() {
        return modeflag;
    }

    void setcachenum(uint32_t cache_tb_num) {
        max_cache_tb_num = cache_tb_num;
    }

    bool inctbnum(uint32_t cur_pc) {
        ++tb_num;
        if (new_tb_map[cur_pc] < 1) {
            ++new_tb_num;
            ++new_tb_map[cur_pc];
            re_tb_num = 0;
            return true;
        } else {
            ++re_tb_num;
            return false;
        }
    }

    void inctbnum2(uint32_t cur_pc) {
        if (new_tb_map[cur_pc] < 1) {
            ++new_tb_num;
            ++new_tb_map[cur_pc];
        }
    }

    uint64_t getnewtbnum() {
        return new_tb_num;
    }

    uint64_t gettbnum() {
        return tb_num;
    }

    uint64_t getretbnum() {
        return re_tb_num;
    }

    void inserttbregs(ConRegs regs) {
        if (cacheconregs.size() < max_cache_tb_num) {
            cacheconregs.push_back(regs);
        } else {
            cacheconregs.pop_front();
            cacheconregs.push_back(regs);
        }
    }

    uint32_t getcachesize() {
        return cacheconregs.size();
    }

    ConRegs getcurtbregs(uint32_t cachePos) {
        return cacheconregs.at(cachePos);
    }

    uint32_t getcurtbpc(uint32_t cachePos) {
        return cacheconregs.at(cachePos)[0];
    }

    uint32_t getcurtbmode(uint32_t cachePos) {
        return cacheconregs.at(cachePos)[1];
    }

    uint32_t getcurtbregssize(uint32_t cachePos) {
        return cacheconregs.at(cachePos).size();
    }

    void insert_current_irq_num(uint32_t irq_num) {
        current_irq_num = irq_num;
    }
};
}

void InvalidStatesDetection::initialize() {

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
        sigc::mem_fun(*this, &InvalidStatesDetection::onTranslateBlockEnd));

    cache_mode = s2e()->getConfig()->getBool(getConfigKey() + ".usePeripheralCache", false);
    init_cache_mode = cache_mode;
    bool ok;
    disable_interrupt_count = 0;
    cache_tb_num = s2e()->getConfig()->getInt(getConfigKey() + ".bb_inv1", 20, &ok);
    max_loop_tb_num = s2e()->getConfig()->getInt(getConfigKey() + ".bb_inv2", 2000, &ok);
    terminate_tb_num = s2e()->getConfig()->getInt(getConfigKey() + ".bb_terminate", 30000, &ok);
    if (cache_mode) {
        terminate_tb_num = terminate_tb_num*0.8;
    }
    initial_terminate_tb_num = terminate_tb_num;
    tb_interval = s2e()->getConfig()->getInt(getConfigKey() + ".tbInterval", 3000, &ok);

    if (!ok || cache_tb_num <= 0 || terminate_tb_num <= 0) {
        getWarningsStream() << "Could not set correct cache and max repeat tb number, \n";
        return;
    }
    getDebugStream() << "cache tb num: " << cache_tb_num << " terminate_tb_num: " << terminate_tb_num
                     << " max_loop_tb_num: " << max_loop_tb_num << "\n";

    kill_point_flag = false;
    alive_point_flag = false;
    ConfigFile *cfg = s2e()->getConfig();
    auto kill_keys = cfg->getIntegerList(getConfigKey() + ".killPoints");
    foreach2 (it, kill_keys.begin(), kill_keys.end()) {
        getDebugStream() << "Add kill point address = " << hexval(*it) << "\n";
        kill_points.push_back(*it);
    }

    auto alive_keys = cfg->getIntegerList(getConfigKey() + ".alivePoints");
    foreach2 (it, alive_keys.begin(), alive_keys.end()) {
        getDebugStream() << "Add alive point address = " << hexval(*it) << "\n";
        alive_points.push_back(*it);
    }

    if (cache_mode) {
        getWarningsStream() << "Invalid States Detection is unabled in cache mode\n";
        return;
    }

    // use for user-defined invlid pc and alive pc
    blockStartConnection = s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &InvalidStatesDetection::onTranslateBlockStart));
    // use for invaild pc
    invalidPCAccessConnection = s2e()->getCorePlugin()->onInvalidPCAccess.connect(
        sigc::mem_fun(*this, &InvalidStatesDetection::onInvalidPCAccess));
}

void InvalidStatesDetection::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t pc, bool staticTarget,
                                                 uint64_t staticTargetPc) {
    signal->connect(
        sigc::bind(sigc::mem_fun(*this, &InvalidStatesDetection::onInvalidLoopDetection), (unsigned) tb->se_tb_type));
}

void InvalidStatesDetection::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                   TranslationBlock *tb, uint64_t pc) {
    signal->connect(sigc::mem_fun(*this, &InvalidStatesDetection::onKillandAlivePoints));
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
    return true;
}

static std::vector<uint32_t> getRegs(S2EExecutionState *state, uint32_t pc) {
    std::vector<uint32_t> conregs;
    bool mode = g_s2e_fast_concrete_invocation;

    conregs.push_back(pc);
    conregs.push_back(mode);
    for (unsigned i = 0; i < 15; ++i) {
        unsigned offset = offsetof(CPUARMState, regs[i]);
        target_ulong concreteData;

        // if (state->regs()->read(offset, &concreteData, sizeof(concreteData), false)) {
        getConcolicValue(state, offset, &concreteData);
        conregs.push_back(concreteData);
        // }
    }

    return conregs;
}

void InvalidStatesDetection::onCacheModeMonitor(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);

    getDebugStream() << "InvalidStatesDetection in cache mode " << plgState->getnewtbnum() << " pc = " << hexval(pc)
                     << " disable_interrupt_count = " << disable_interrupt_count
                     << " interrupt flag = " << state->regs()->getInterruptFlag() << "\n";

    if (plgState->inctbnum(pc)) {
        getInfoStream() << "The unqiue number of the executed basic blocks in current state is "
                            << plgState->getnewtbnum() << " pc = " << hexval(pc) << "\n";
    }

    // we should make sure new tb in normal mode will be executed after interrupt
    // in case too frequent interrupts
    if (state->regs()->getInterruptFlag()) {
        disable_interrupt_count = cache_tb_num;
    } else {
        if (disable_interrupt_count > 0) {
            disable_interrupt_count--;
        }
    }

    if (disable_interrupt_count == 0) {
        g_s2e_allow_interrupt = 1;
    } else {
        g_s2e_allow_interrupt = 0;
    }

    if (!state->regs()->getInterruptFlag()) {
        if (plgState->gettbnum() != 0 && plgState->gettbnum() % tb_interval == 0) {
            getDebugStream() << " force exit every max loop tb num " << plgState->gettbnum() << "\n";
            g_s2e_allow_interrupt = 1;
            s2e()->getExecutor()->setCpuExitRequest();
        }
    }
}

void InvalidStatesDetection::onInvalidStatesKill(S2EExecutionState *state, uint64_t pc, InvalidStatesType type,
                                                 std::string reason_str) {
    DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);

    onInvalidStatesEvent.emit(state, pc, type, plgState->getnewtbnum());
    std::string s;
    llvm::raw_string_ostream ss(s);
    ss << reason_str << state->getID() << " pc = " << hexval(state->regs()->getPc()) << " tb num "
       << plgState->getnewtbnum() << "\n";
    ss.flush();
    s2e()->getExecutor()->terminateState(*state, s);
}

bool InvalidStatesDetection::onModeSwitchandTermination(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);
    // cache mode to learning mode switch
    if (cache_mode && !g_s2e_cache_mode) {
        blockStartConnection = s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &InvalidStatesDetection::onTranslateBlockStart));

        invalidPCAccessConnection = s2e()->getCorePlugin()->onInvalidPCAccess.connect(
            sigc::mem_fun(*this, &InvalidStatesDetection::onInvalidPCAccess));
        getInfoStream() << "mode switch!! path killer is enable\n";
        plgState->reset_allcache();
        cache_mode = false;
        return false;
    }

    // learning mode termination and switch to cache mode
    if (plgState->getnewtbnum() > 200 && plgState->getretbnum() > terminate_tb_num &&
        (state->regs()->getInterruptFlag() == 0)) {
        bool actual_end = false;
        if (terminate_tb_num > 2*initial_terminate_tb_num) {
            actual_end = true;
        }
        onLearningTerminationEvent.emit(state, &actual_end, plgState->getnewtbnum());
        if (actual_end) {
            getInfoStream(state) << " mode switch current pc = " << hexval(pc) << "\n";
            cache_mode = true;
            plgState->reset_allcache();
            invalidPCAccessConnection.disconnect();
            blockStartConnection.disconnect();
            return true;
        } else {
            terminate_tb_num += 0.05 * terminate_tb_num;
            return false;
        }
    }
    return false;
}

void InvalidStatesDetection::onKillandAlivePoints(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);
    // kill points defined by users
    for (auto kill_point : kill_points) {
        if (kill_point == pc) {
            plgState->inckpcount(pc);
            if (plgState->getkpcount(pc) > 0) {
                kill_point_flag = true;
                break;
            }
        }
    }

    // have alive points or not
    for (auto alive_point : alive_points) {
        if (alive_point == pc) {
            alive_point_flag = true;
            break;
        }
    }
}

void InvalidStatesDetection::onInvalidPCAccess(S2EExecutionState *state, uint64_t addr) {
    DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);
    if (!init_cache_mode) {
        getWarningsStream() << "Invalid memory (" << hexval(addr) << ") access\n";
        std::string reason_str = "Kill State due to invalid memory access:";
        onInvalidStatesKill(state, state->regs()->getPc(), IM, reason_str);
    } else {
        bool actual_end = true;
        onLearningTerminationEvent.emit(state, &actual_end, plgState->getnewtbnum());
    }
}

void InvalidStatesDetection::onInvalidLoopDetection(S2EExecutionState *state, uint64_t pc, unsigned source_type) {
    DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);

    // cache mode
    if (g_s2e_cache_mode) {
        onCacheModeMonitor(state, pc);
        return;
    }

    if (onModeSwitchandTermination(state, pc)) {
        // learning mode termination
        return;
    }

    // normal mode
    // we should make sure new tb in normal mode will be executed after interrupt
    // in case too frequent interrupts
    if (state->regs()->getInterruptFlag()) {
        disable_interrupt_count = cache_tb_num;
    } else {
        if (disable_interrupt_count > 0) {
            disable_interrupt_count--;
        }
    }

    if (disable_interrupt_count == 0) {
        g_s2e_allow_interrupt = 1;
    } else {
        g_s2e_allow_interrupt = 0;
    }

    // update re and new tb number
    if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) {
        plgState->inctbnum2(pc); // only counter new tb in irq
    } else {
        if (plgState->inctbnum(pc)) {
            getInfoStream() << "InvalidStatesDetection in learning mode new tb num = " << plgState->getnewtbnum()
                                << " pc = " << hexval(pc) << "\n";
        }
    }

    plgState->setmaxloopnum(max_loop_tb_num);
    plgState->setcachenum(cache_tb_num);
    std::vector<uint32_t> conregs = getRegs(state, pc);

    getInfoStream(state) << state->regs()->getInterruptFlag() << " current pc = " << hexval(pc) << " re tb num "
                             << plgState->getretbnum() << " concrete mode: " << conregs[1] << "\n";

    // kill points defined by users
    if (kill_point_flag) {
        kill_point_flag = false;
        std::string reason_str = "Kill State due to user-defined kill points:";
        onInvalidStatesKill(state, pc, UKP, reason_str);
    }

    // have alive points or not
    for (auto alive_point : alive_points) {
        if (alive_point == pc) {
            alive_point_flag = true;
            break;
        }
    }

    if (alive_point_flag) {
        alive_point_flag = false;
        g_s2e_allow_interrupt = 2; // continue wait for irq
        plgState->setloopflag(false);
        plgState->inserttbregs(conregs);
        getWarningsStream() << " cannot kill dead loop caused by alive tb in loop\n";
        s2e()->getExecutor()->setCpuExitRequest();
        return;
    }

    // if already at least on tb is same, compare other tbs in loop
    if (plgState->getloopflag()) {
        std::vector<uint32_t> loopregs = plgState->getcurloopregs();
        int k;
        for (k = 0; k < conregs.size(); ++k) {
            if (loopregs[k] == conregs[k] || k == 1) {
                continue;
            } else {
                break;
            }
        }

        if (k == conregs.size()) {
            plgState->poploopregs();

            // at least one tb is symbolic
            if (conregs[1] == 0) {
                plgState->setmodeflag(true);
            }

            if (plgState->getloopsize() == 0) {
                if (plgState->getmodeflag()) {
                    std::string reason_str = "Kill State due to dead loop (multi-tbs):";
                    onInvalidStatesKill(state, pc, DL2, reason_str);
                } else {
                    getWarningsStream() << " cannot kill dead loop in concrete mode pc = " << hexval(pc) << "\n";
                    g_s2e_allow_interrupt = 2; // continue wait for irq
                    plgState->setloopflag(false);
                    plgState->inserttbregs(conregs);
                    s2e()->getExecutor()->setCpuExitRequest();
                    return;
                }
            } else {
                plgState->inserttbregs(conregs);
                return;
            }
        } else {
            getDebugStream() << " state: " << state->getID() << " loop reg " << k - 2 << " = " << hexval(loopregs[k])
                             << " cache reg = " << k - 2 << " is " << hexval(conregs[k]) << " different \n";
            if (k > 1 && !state->regs()->getInterruptFlag()) {
                UniquePcRegMap uniquepcregmap = std::make_pair(pc, k - 2);
                if (plgState->judgelongloopregs(uniquepcregmap, conregs[k])) {
                    plgState->setloopflag(false);
                    std::string reason_str = "Kill State due to long loop (multi-tbs): ";
                    onInvalidStatesKill(state, pc, LL2, reason_str);
                }
            }
            plgState->setloopflag(false);
            plgState->inserttbregs(conregs);
            return;
        }
    }

    // if we find at least on tb is different in loop, then we continue compare other cache tb
    int i, j;
    std::tuple<uint32_t /* pc */, uint32_t /* reg_num */, uint32_t /* value */> last_re_reg_map;
    for (i = 0; i < plgState->getcachesize(); ++i) {
        if (conregs.size() != plgState->getcurtbregssize(i)) {
            continue;
        }
        std::vector<uint32_t> cacheregs = plgState->getcurtbregs(i);
        // already compare pc and mode, so j begin with 2
        for (j = 0; j < conregs.size(); ++j) {
            if (cacheregs[j] == conregs[j]) {
                continue;
            } else {
                break;
            }
        }

        if (j == conregs.size()) { // TODO: if only one reg is different, we should also go to long loop check.
            if (i == plgState->getcachesize() - 1) {
                if (conregs[1] == 0) {
                    // only one tb in loop, kill directly if it is in symbolic mode
                    std::string reason_str = "Kill State due to Dead Loop (single tb): ";
                    single_dead_loop[pc]++;
                    if (single_dead_loop[pc] > 1) {
                        kill_points.push_back(pc);
                    }
                    onInvalidStatesKill(state, pc, DL1, reason_str);
                } else {
                    getWarningsStream() << " cannot kill dead single loop in concrete mode" << plgState->getnewtbnum()
                                        << "\n";
                    plgState->inserttbregs(conregs);
                    s2e()->getExecutor()->setCpuExitRequest();
                    return;
                }
            } else {
                if (conregs[1] == 0) {
                    plgState->setmodeflag(true);
                } else {
                    plgState->setmodeflag(false);
                }
                plgState->inserttbregs(conregs); // insert current tb before assign loop tb
                plgState->assignloopregs(i);     // assign loop tb
                plgState->setloopflag(true);     // next round compare loop tb first
                getDebugStream(state) << " Same as the " << i << " current pc = " << hexval(pc)
                                      << " cachereg pc = " << hexval(cacheregs[0]) << " \n";
                return;
            }
        } else {
            if (j > 1 && plgState->getnewtbnum() > 200) {
                last_re_reg_map = std::make_tuple(pc, j - 2, conregs[j]);
            }
        }
    }

    // monitor long loop in single tb circle
    if (std::get<0>(last_re_reg_map) == pc) {
        UniquePcRegMap uniquepcregmap = std::make_pair(pc, std::get<1>(last_re_reg_map));
        getDebugStream(state) << " pc = " << hexval(std::get<0>(last_re_reg_map)) << " long reg "
                              << hexval(std::get<1>(last_re_reg_map)) << " is " << hexval(std::get<2>(last_re_reg_map))
                              << " different \n";
        if (plgState->judgelongloopregs(uniquepcregmap, std::get<2>(last_re_reg_map))) {
            // max_loop_tb_num++;
            std::string reason_str = "Kill State due to long loop (single-tb):";
            onInvalidStatesKill(state, pc, LL1, reason_str);
        }
    }

    plgState->inserttbregs(conregs);
}

// only used in unit test addition confirmation
/* static bool unittesthook(S2EExecutionState *state, uint32_t pc) { */
// std::vector<uint32_t> conregs;

// for (unsigned i = 0; i < 15; ++i) {
// unsigned offset = offsetof(CPUARMState, regs[i]);
// target_ulong concreteData;

// //if (state->regs()->read(offset, &concreteData, sizeof(concreteData), false)) {
// getConcolicValue(state, offset, &concreteData);
// conregs.push_back(concreteData);
// // }
// }

// if (pc == 0x800306c || pc == 0x80034b6 || pc == 0x8003058 || pc == 0x8001c6e) {
// for (int j = 0; j < 13; j++) {
// g_s2e->getDebugStream() << hexval(pc) << "Check  point R" << j << " = " << hexval(conregs[j]) << "\n";
// }
// }

// return true;

/* } */

// only used for addtional log
/*void InvalidStatesDetection::recordTBMap(S2EExecutionState *state) {*/
// DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);
// std::string fileName;
// fileName = s2e()->getOutputDirectory() + "/" + "state" + std::to_string(state->getID()) + "_tb_map.dat";
// std::ofstream fTBmap;
// fTBmap.open(fileName, std::ios::out | std::ios::trunc);

// for (auto ittb : plgState->getuniquetbmap()) {
// fTBmap << "tb : " << hexval(ittb.first) << std::endl;;
//}

// fTBmap.close();
/*}*/

} // namespace plugins
} // namespace s2e
