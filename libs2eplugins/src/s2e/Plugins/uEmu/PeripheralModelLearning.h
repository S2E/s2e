///
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_PeripheralModelLearning_H
#define S2E_PLUGINS_PeripheralModelLearning_H

#include <deque>
#include <inttypes.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/uEmu/ARMFunctionMonitor.h>
#include <s2e/Plugins/uEmu/InvalidStatesDetection.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/SymbolicHardwareHook.h>
#include <vector>

#include <llvm/ADT/SmallVector.h>

namespace s2e {
namespace plugins {
enum PeripheralRegisterType { TIRQS, TIRQC, T0, T1, PT1, T2, T3 }; // IRQ Type only used in KB
enum KBUpdateReason { Valid, Invlid };
namespace hw {
typedef std::vector<uint8_t> ConcreteArray;
typedef std::pair<uint64_t, uint64_t> SymbolicMmioRange;
typedef llvm::SmallVector<SymbolicMmioRange, 4> SymbolicMmioRanges;
typedef std::pair<uint32_t /* peripheraladdress */, uint32_t /* pc */> UniquePeripheral;
typedef std::map<uint32_t /* peripheraladdress */, uint32_t /* kind of type */> TypeFlagPeripheralMap;
typedef std::map<uint32_t /* peripheraladdress */, uint32_t /* size */> UniquePeripheralSizeMap;
typedef std::map<uint32_t /* peripheraladdress */, uint32_t /* last write value */> WritePeripheralMap;
typedef std::map<uint64_t /* caller pc&function regs hash value*/, uint32_t /* value */> CWMap;
typedef std::pair<uint64_t /* unique no */, uint32_t /* value */> NumPair;

typedef std::map<uint32_t /* peripheraladdress */,
                 std::map<uint32_t /* pc */, std::pair<uint64_t /* caller pc&function regs hash value */, NumPair>>>
    T0PeripheralMap;
typedef std::map<UniquePeripheral, uint32_t /* value */> T1PeripheralMap;
typedef std::map<UniquePeripheral, std::pair<uint64_t /* caller pc&function regs hash value */, uint32_t /* value */>>
    T1BPeripheralMap;
typedef std::map<UniquePeripheral, std::pair<uint64_t /* caller pc&function regs hash value */, NumPair>>
    T1BNPeripheralMap;
typedef std::map<UniquePeripheral, CWMap> T2PeripheralMap;
typedef std::map<UniquePeripheral, uint32_t /* last fork count */> PeripheralForkCount;

typedef std::map<uint32_t /* phaddr */, uint32_t /* value */> PeripheralMap;
typedef std::map<uint32_t /* CR phaddr */, std::map<uint32_t /* CR value */, std::deque<uint32_t>>> IRQCRMap;
typedef std::map<UniquePeripheral, uint32_t /* irq_no */> IRQSRMap;
typedef std::pair<uint32_t /* IRQ No */, uint32_t /* phaddr */> IRQPhPair;
typedef std::map<IRQPhPair /* phaddr */, uint32_t /* flag */> TIRQPeripheralMapFlag;
typedef std::map<IRQPhPair /* phaddr */, IRQCRMap> TIRQCPeripheralMap;
typedef std::tuple<uint32_t, /* irq no */ uint32_t /* phaddr */, uint32_t /* pc */> IRQPhTuple;
typedef std::map<IRQPhTuple /* phaddr */, uint32_t /* flag */> TIRQSPeripheralMapFlag;
typedef std::map<IRQPhTuple, std::deque<uint32_t>> TIRQSPeripheralMap;
typedef std::map<uint32_t /* phaddr */, std::deque<uint32_t>> T3PeripheralMap;
typedef std::map<uint64_t /* unique no */, uint32_t /* value */> NumMap;
typedef std::map<uint64_t /* caller pc&function regs hash value */, NumPair> CWNOMap;
typedef std::map<UniquePeripheral, CWNOMap> AllKnowledgeBaseMap;
typedef std::map<uint32_t /* phaddr */, NumMap> AllKnowledgeBaseNoMap;

typedef std::map<uint32_t /* peripheraladdress */, std::pair<uint32_t /* size */, uint32_t /* count */>>
    ReadPeripheralMap;
typedef std::pair<uint32_t /* peripheraladdress */, std::pair<uint32_t /* size */, uint32_t /* count */>> ReadTUPLE;
typedef std::tuple<uint32_t /* phaddr */, uint32_t /* pc */, uint32_t /* caller pc&function regs hash value */> T2Tuple;
typedef std::vector<std::vector<S2EExecutionState *>> ForkStateStack;

class PeripheralModelLearning : public Plugin {
    S2E_PLUGIN

private:
    SymbolicMmioRanges m_mmio;
    sigc::connection onStateKillConnection;
    sigc::connection onStateForkConnection;
    sigc::connection onStateForkDecideConnection;
    sigc::connection onStateSwitchConnection;
    sigc::connection onSymbolicAddressConnection;
    sigc::connection onInterruptExitonnection;
    InvalidStatesDetection *onInvalidStateDectionConnection;
    ARMFunctionMonitor *onARMFunctionConnection;

    // dynamic analysis mode
    T1BPeripheralMap cache_t1_type_phs;
    T1BPeripheralMap cache_pt1_type_phs;
    T1PeripheralMap cache_t1_type_flag_phs; // 1: indicates t1 2: indicates pt1
    T1PeripheralMap cache_t2_type_flag_phs;
    T2PeripheralMap cache_t2_type_phs;
    T3PeripheralMap cache_t3_type_phs_backup;
    T3PeripheralMap cache_t3_type_phs;
    TIRQCPeripheralMap cache_tirqc_type_phs;
    TIRQSPeripheralMap cache_tirqs_type_phs;
    TIRQPeripheralMapFlag cache_type_irqc_flag;
    TIRQSPeripheralMapFlag cache_type_irqs_flag;
    TypeFlagPeripheralMap cache_type_flag_phs;
    UniquePeripheralSizeMap cache_dr_type_size;
    //  knowledge extraction mode
    TypeFlagPeripheralMap
        irq_data_phs; // 2: donates data reg in interrupt which should not meet conditions in irq handle
    AllKnowledgeBaseNoMap cache_all_cache_phs;
    IRQSRMap possible_irq_srs;
    TIRQSPeripheralMap possible_irq_values;
    TIRQSPeripheralMap impossible_irq_values;
    TIRQSPeripheralMap already_used_irq_values;
    uint64_t all_peripheral_no;
    std::map<uint64_t /* path num */, uint32_t /* flag */> all_path_map;
    std::map<uint64_t /* path num */, uint32_t /* flag */> all_searched_path_map;

    std::map<uint32_t /*irq no*/, PeripheralMap> irq_crs;
    std::map<uint32_t /*irq no*/, std::deque<uint32_t>> irq_srs;
    uint32_t t2_max_context;
    uint32_t t3_max_symbolic_count;
    bool auto_mode_switch;

    uint32_t round_count;    // learning count
    bool no_new_branch_flag; // use to judge whether new states has been forked casued by possiable status phs
    bool irq_no_new_branch_flag;
    std::vector<S2EExecutionState *> irq_states;           // forking states in interrupt
    std::vector<S2EExecutionState *> false_irq_states;     // forking states in interrupt
    std::vector<S2EExecutionState *> learning_mode_states; // forking states in interrupt
    ForkStateStack unsearched_condition_fork_states;       // all forking states
    int fs;                                                // count for false status fork states kill;
    std::vector<S2EExecutionState *> false_type_phs_fork_states;
    std::map<uint32_t, uint32_t> symbolic_address_count; // record symbolic address

    std::string fileName;
    std::string firmwareName;
    bool enable_extended_irq_mode;
    bool enable_fuzzing;
    bool allow_new_phs;
    std::vector<uint32_t> valid_phs;

    time_t start, end;
    uint64_t durationtime;

    template <typename T> bool parseRangeList(ConfigFile *cfg, const std::string &key, T &result);
    bool parseConfigIoT();
    template <typename T, typename U> inline bool isSymbolic(T ports, U port);

    bool ConcreteT3Regs(S2EExecutionState *state);
    void updateIRQKB(S2EExecutionState *state, uint32_t irq_no, uint32_t flag);
    void updateGeneralKB(S2EExecutionState *state, uint32_t irq_num, uint32_t reason_flag);
    bool getPeripheralExecutionState(std::string variablePeripheralName, uint32_t *phaddr, uint32_t *pc,
                                     uint64_t *regs_hash, uint64_t *no);
    bool readKBfromFile(std::string fileName);
    bool getGeneralEntryfromKB(std::string variablePeripheralName, uint32_t *type, uint32_t *phaddr, uint32_t *pc,
                               uint32_t *value, uint64_t *cw_value);
    bool getIRQEntryfromKB(std::string variablePeripheralName, uint32_t *irq_no, uint32_t *type, uint32_t *phaddr,
                           uint32_t *cr_phaddr, uint32_t *value, uint32_t *cr_value);
    bool getDREntryfromKB(std::string variablePeripheralName, uint32_t *type,
                           uint32_t *phaddr, uint32_t *size);
    void saveKBtoFile(S2EExecutionState *state, uint64_t tb_num);
    void writeTIRQPeripheralstoKB(S2EExecutionState *state, std::ofstream &fPHKB);
    void identifyDataPeripheralRegs(S2EExecutionState *state, std::ofstream &fPHKB);

public:
    sigc::signal<void, S2EExecutionState *, PeripheralRegisterType /* type */, uint64_t /* physicalAddress */,
                 uint32_t /* t3 rest count */, uint32_t * /* size */, uint32_t * /* fuzz input */,
                 bool * /* enable fuzz */>
        onFuzzingInput;

    sigc::signal<void, S2EExecutionState *, bool /* fuzzing to learning mode */> onModeSwitch;

    sigc::signal<void, S2EExecutionState *, uint64_t /* phaddr */> onInvalidPHs;

    PeripheralModelLearning(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    bool isMmioSymbolic(uint64_t physAddr);

    klee::ref<klee::Expr> switchModefromFtoL(S2EExecutionState *state, std::string ss, uint32_t phaddr, unsigned size,
                                             uint64_t concreteValue);
    void switchModefromLtoF(S2EExecutionState *state);

    klee::ref<klee::Expr> onLearningMode(S2EExecutionState *state, SymbolicHardwareAccessType type, uint64_t address,
                                         unsigned size, uint64_t concreteValue);
    klee::ref<klee::Expr> onFuzzingMode(S2EExecutionState *state, SymbolicHardwareAccessType type, uint64_t address,
                                        unsigned size, uint64_t concreteValue);
    void onWritePeripheral(S2EExecutionState *state, uint64_t phaddr, const klee::ref<klee::Expr> &value);
    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);
    void onEngineShutdown();
    void onInvalidStatesDetection(S2EExecutionState *state, uint32_t pc, InvalidStatesType type, uint64_t tb_num);
    void onLearningTerminationDetection(S2EExecutionState *state, bool *actual_end, uint64_t tb_num);
    void onExceptionExit(S2EExecutionState *state, uint32_t irq_no);
    void onStateKill(S2EExecutionState *state);
    void onStateSwitch(S2EExecutionState *current, S2EExecutionState *next);
    void onStateForkDecide(S2EExecutionState *state, bool *doFork, const klee::ref<klee::Expr> &condition,
                           bool *conditionFork);
    void onSymbolicAddress(S2EExecutionState *state, klee::ref<klee::Expr> virtualAddress, uint64_t concreteAddress,
                           bool &concretize, CorePlugin::symbolicAddressReason reason);
    void onARMFunctionReturn(S2EExecutionState *state, uint32_t return_pc);
    void onARMFunctionCall(S2EExecutionState *state, uint32_t caller_pc, uint64_t function_hash);

    // only used for symbolic compairtion test verion
    /*klee::ref<klee::Expr> onLearningModeTest(S2EExecutionState *state, SymbolicHardwareAccessType type, uint64_t
     * address,*/
    // unsigned size, uint64_t concreteValue);
    // void onForkTest(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
    // const std::vector<klee::ref<klee::Expr>> &newConditions);
    // void onTerminationDetectionTest(S2EExecutionState *state, bool availablestate, uint64_t tb_num);
    // void onStateForkDecideTest(S2EExecutionState *state, bool *doFork,
    /*const klee::ref<klee::Expr> &condition, bool *conditionFork);*/
};

} // namespace hw
} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_PeripheralModelLearning_H
