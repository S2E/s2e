///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_InvalidStatesDetection_H
#define S2E_PLUGINS_InvalidStatesDetection_H

#include <deque>
#include <llvm/ADT/DenseMap.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {
typedef std::pair<uint32_t /* pc */, uint32_t /* reg num */> UniquePcRegMap;
typedef std::vector<uint32_t> ConRegs;
typedef std::deque<ConRegs> CacheConregs;
typedef llvm::DenseMap<uint32_t, uint32_t> TBCounts;
enum InvalidStatesType { DL1, DL2, LL1, LL2, UKP, IM };

class InvalidStatesDetection : public Plugin {
    S2E_PLUGIN
public:
    InvalidStatesDetection(S2E *s2e) : Plugin(s2e) {
    }

    struct MEM {
        uint32_t baseaddr;
        uint32_t size;
    };

    void initialize(void);

    sigc::signal<void, S2EExecutionState *, uint32_t /* PC */, InvalidStatesType /* invalid state type */, uint64_t /* unique tb num */>
        onInvalidStatesEvent;

    sigc::signal<void, S2EExecutionState *, bool * /* succuess or not */, uint64_t /* unique tb num */>
        onLearningTerminationEvent;

private:
    sigc::connection invalidPCAccessConnection;
    sigc::connection blockStartConnection;
    uint32_t cache_tb_num;
    uint64_t initial_terminate_tb_num;
    uint64_t terminate_tb_num;
    uint64_t max_loop_tb_num;
    uint32_t disable_interrupt_count;
    uint32_t tb_interval;
    std::vector<uint32_t> kill_points;
    std::map<uint32_t, uint32_t> single_dead_loop;
    std::vector<uint32_t> alive_points;
    bool cache_mode;
    bool init_cache_mode;
    bool alive_point_flag;
    bool kill_point_flag;

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool staticTarget, uint64_t staticTargetPc);

    void onInvalidPCAccess(S2EExecutionState *state, uint64_t addr);

    void onInvalidLoopDetection(S2EExecutionState *state, uint64_t pc, unsigned source_type);

    void onKillandAlivePoints(S2EExecutionState *state, uint64_t pc);

    void onCacheModeMonitor(S2EExecutionState *state, uint64_t pc);

    void onInvalidStatesKill(S2EExecutionState *state, uint64_t pc, InvalidStatesType type, std::string reason_str);

    bool onModeSwitchandTermination(S2EExecutionState *state, uint64_t pc);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_InvalidStatesDetection_H
