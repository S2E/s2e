///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_NLPPeripheralModel_H
#define S2E_PLUGINS_NLPPeripheralModel_H

#include <boost/regex.hpp>
#include <queue>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/SEmu/ExternalHardwareSignal.h>
#include <s2e/Plugins/SymbolicHardware/SymbolicHardware.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/SymbolicHardwareHook.h>
#include <utility>

namespace s2e {
static const boost::regex TARegEx("([a-zA-Z\\d\\#\\*,=></]+)", boost::regex::perl);

namespace plugins {

typedef struct datareg {
    uint32_t t_size;
    uint32_t r_size;
    uint32_t t_value;
    std::queue<uint8_t> r_value;
    datareg() : t_size(0), r_size(0), t_value(0) {
    }
} DataReg;

typedef struct reg {
    std::string type;
    uint32_t phaddr;
    uint32_t width;
    uint32_t data_width;
    uint32_t reset;
    DataReg dr;
    bool is_eth;
    uint32_t cur_value;
    reg() : is_eth(false) {
    }
} Reg;

typedef struct equation {
    uint32_t id;
    std::string type_eq; //
    Field a1;
    std::string eq;      //= ; >;  <;  >=; <=
    std::string type_a2; // V:value; R: receive; T: transmit; F: field
    uint32_t a2_value;
    Field a2_field;
    int32_t interrupt;
    int32_t dma_irq;
    bool rel;
    equation() : id(0), type_eq("A"), interrupt(-1), dma_irq(-1), rel(false) {
    }
} Equation;

enum FLAGType { Flip, Rand, Counter, Fix };

typedef struct flag {
    uint32_t id;
    Field a1;
    FLAGType tag;
    std::vector<long> value;
} Flag;

typedef struct dma {
    uint32_t id;
    uint32_t dma_irq;
    Field memo_field;
    Field peri_field;
    // Field size_field;
    Field HTIF;
    Field TCIF;
    Field GIF;
    uint32_t state;
} DMA;

typedef std::map<uint32_t, Reg> RegMap;
typedef std::vector<Equation> EquList;
typedef std::pair<EquList, EquList> TA;
typedef std::map<std::string, std::map<uint32_t, std::vector<TA>>> TAMap;
typedef std::map<uint32_t, std::vector<Flag>> FlagList;

class NLPPeripheralModel : public Plugin {
    S2E_PLUGIN
public:
    NLPPeripheralModel(S2E *s2e) : Plugin(s2e) {
    }
    sigc::signal<void, S2EExecutionState *, uint32_t /* irq_no */, bool * /* actual trigger or not */>
        onExternalInterruptEvent;
    sigc::signal<void, S2EExecutionState *, std::vector<uint32_t> * /* enable IRQ vector */> onEnableISER;
    sigc::signal<void, S2EExecutionState *, uint32_t, uint32_t> onHardwareWrite;
    sigc::signal<void, S2EExecutionState *, uint32_t, uint32_t> onFirmwareWrite;
    sigc::signal<void, S2EExecutionState *, uint32_t, uint32_t> onFirmwareRead;
    sigc::signal<void, S2EExecutionState *, uint32_t, uint32_t> onFirmwareCondition;

private:
    ExternalHardwareSignal *onExternalHardwareSignalConnection;

    hw::PeripheralMmioRanges nlp_mmio;
    std::string NLPfileName;
    RegMap regs;
    std::set<uint32_t> data_register;
    TAMap all_rules;
    FlagList all_counters;
    std::vector<DMA> all_dmas;
    std::vector<uint32_t> irq_no;

    uint32_t fork_point;
    uint32_t disable_interrupt_count = 0;
    bool init_dr_flag = false;
    uint32_t rw_count;
    std::set<uint32_t> unenabled_flag;
    std::set<uint32_t> untriggered_irq;
    std::map<uint32_t, std::set<uint64_t>> read_unauthorized_freq;
    std::map<uint32_t, std::set<uint64_t>> write_unauthorized_freq;

    bool checked_SR = false;

    template <typename T> bool parseRangeList(ConfigFile *cfg, const std::string &key, T &result);
    bool parseConfig();
    void initialize();

    bool readNLPModelfromFile(S2EExecutionState *state, std::string &fileName);
    bool getMemo(std::string &peripheralcache, Reg &reg);
    bool getTApairs(std::string &peripheralcache, EquList &trigger, EquList &action);
    bool extractEqu(std::string &peripheralcache, EquList &vec, bool rel, bool is_trigger);
    bool extractFlag(std::string &peripheralcache, Flag &flag);
    std::vector<long> getBits(std::string &bits);
    std::pair<std::string, uint32_t> getAddress(std::string &addr);
    void recordRule(uint32_t addr, TA &rule);
    bool extractDMA(std::string &peripheralcache, DMA &dma);
    void SplitString(const std::string &s, std::vector<std::string> &v, const std::string &c);
    void SplitStringToInt(const std::string &s, std::vector<long> &v, const std::string &c, int dtype);

    void onPeripheralRead(S2EExecutionState *state, SymbolicHardwareAccessType type, uint32_t phaddr, unsigned size,
                          uint32_t *NLPsymbolicvalue, bool *flag, std::stringstream *ss);
    void onPeripheralWrite(S2EExecutionState *state, SymbolicHardwareAccessType type, uint32_t phaddr,
                           uint32_t writeconcretevalue);
    void hardware_write_to_receive_buffer(S2EExecutionState *state, uint32_t phaddr = 0);
    std::pair<uint32_t, uint32_t> AddressCorrection(S2EExecutionState *state, uint32_t phaddr);

    void deal_rule_O(S2EExecutionState *state);
    void deal_rule_RWVB(S2EExecutionState *state, uint32_t address, std::string rule_type);
    void deal_rule_flag(S2EExecutionState *state, uint32_t phaddr);
    uint32_t get_reg_value(S2EExecutionState *state, RegMap &state_map, Field &a);
    void set_reg_value(S2EExecutionState *state, RegMap &state_map, Field &a, uint32_t value);
    void take_action(S2EExecutionState *state, EquList &actions, bool buffer_related);
    bool ExistInMMIO(uint32_t tmp);
    bool EmitIRQ(S2EExecutionState *state, int irq);
    bool compare(uint32_t a1, std::string &sym, uint32_t a2);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool staticTarget, uint64_t staticTargetPc);
    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onFeedData(S2EExecutionState *state, uint64_t pc);
    void onForkPoints(S2EExecutionState *state, uint64_t pc, unsigned source_type);
    void onExceptionExit(S2EExecutionState *state, uint32_t irq_no);
    void onStatistics();
    void CheckEnable(S2EExecutionState *state, std::vector<uint32_t> &irq_no);
    void onEnableReceive(S2EExecutionState *state, uint32_t pc, uint64_t tb_num);

    void onUpdateBySignals(S2EExecutionState *state, SignalPair &irq_signals);
    void onFirmwareFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);
    bool checkField(S2EExecutionState *state, FieldList &fields);
    bool getPeripheralExecutionState(std::string variablePeripheralName, uint32_t *phaddr, uint32_t *size, uint32_t *pc,
                                     uint64_t *no);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_NLPPeripheralModel_H
