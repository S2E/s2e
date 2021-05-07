///
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <boost/regex.hpp>
#include <klee/util/ExprUtil.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include "PeripheralModelLearning.h"

#include <llvm/Support/CommandLine.h>

using namespace klee;

namespace {
llvm::cl::opt<bool> DebugSymbHw("debug-symbolic-hardware", llvm::cl::init(true));
}

namespace s2e {
namespace plugins {
namespace hw {

extern "C" {
static bool symbhw_is_mmio_symbolic(struct MemoryDesc *mr, uint64_t physaddr, uint64_t size, void *opaque);
}

static klee::ref<klee::Expr> symbhw_symbread(struct MemoryDesc *mr, uint64_t physaddress,
                                             const klee::ref<klee::Expr> &value, SymbolicHardwareAccessType type,
                                             void *opaque);

static void symbhw_symbwrite(struct MemoryDesc *mr, uint64_t physaddress, const klee::ref<klee::Expr> &value,
                             SymbolicHardwareAccessType type, void *opaque);

static const boost::regex KBGeneralPeripheralRegEx("(.+)_(.+)_(.+)_(.+)_(.+)", boost::regex::perl);
static const boost::regex KBIRQPeripheralRegEx("(.+)_(.+)_(.+)_(.+)_(.+)_(.+)", boost::regex::perl);
static const boost::regex KBDRPeripheralRegEx("(.+)_(.+)_(.+)_(.+)", boost::regex::perl);
static const boost::regex PeripheralModelLearningRegEx("v\\d+_iommuread_(.+)_(.+)_(.+)", boost::regex::perl);

S2E_DEFINE_PLUGIN(PeripheralModelLearning, "PeripheralModelLearning S2E plugin", "PeripheralModelLearning",
                  "InvalidStatesDetection", "ARMFunctionMonitor");

namespace {
class PeripheralModelLearningState : public PluginState {
private:
    AllKnowledgeBaseMap lastforkphs;
    std::pair<uint32_t, std::vector<uint32_t>> last_fork_cond;
    std::map<uint32_t /* irq num */, AllKnowledgeBaseMap> irq_lastforkphs;
    std::map<uint32_t /* pc */, uint32_t /* count */> irqfork_count;
    std::map<uint32_t /* pc */, uint32_t /* count */> alive_points_count;
    WritePeripheralMap write_phs;
    ReadPeripheralMap read_phs;          // map pair with count rather that value
    TypeFlagPeripheralMap type_flag_phs; // use to indicate control phs map but don't store the value
    TypeFlagPeripheralMap all_rw_phs;    // use to indicate control phs map but don't store the value
    TypeFlagPeripheralMap condition_phs; // record all phs which meet conditions
    TypeFlagPeripheralMap lock_t1_type_flag;
    TypeFlagPeripheralMap t0_type_flag_phs; // use to indicate which t0 phs have been read
    TypeFlagPeripheralMap t3_size_map;      // use to indicate t3 ph size
    T1PeripheralMap symbolicpc_phs;         // 1 means this phs have been read as pc
    T1PeripheralMap symbolicpc_phs_fork_count;
    T0PeripheralMap t0_type_phs;
    T1BNPeripheralMap t1_type_phs;
    T1PeripheralMap pdata_type_phs; // for only one time reading becase t1 is stored in second time reading
    T1BNPeripheralMap pt1_type_phs;
    T1PeripheralMap
        pt1_type_flag_phs;            // 1 means this reg has never been read as seed; 2 means already been read as seed
    T1PeripheralMap t2_type_flag_phs; // If t2 or not (base on phaddr & pc)
    T2PeripheralMap pt2_type_flag_phs; // 1 means this reg has never been read as t2; 2 means already been read
    T2PeripheralMap t2_type_phs;
    TIRQCPeripheralMap tirqc_type_phs; // store the control ph values corresponding to the regs has
    TypeFlagPeripheralMap type_irq_flag;
    PeripheralForkCount ph_forks_count;
    std::map<uint32_t /* irq no */, std::deque<uint64_t>> hash_stack;
    TypeFlagPeripheralMap concrete_t3_flag;
    T3PeripheralMap t3_type_phs;
    std::deque<UniquePeripheral> current_irq_phs_value;
    AllKnowledgeBaseNoMap allcache_phs; // save every value for all phs read (once for each read)
    // TIRQSPeripheralMap tirqs_type_phs;
    // TWHCPeripheralMap twhc_type_phs; // twhc type
public:
    PeripheralModelLearningState() {
        write_phs.clear();
    }

    virtual ~PeripheralModelLearningState() {
    }

    static PluginState *factory(Plugin *, S2EExecutionState *) {
        return new PeripheralModelLearningState();
    }

    PeripheralModelLearningState *clone() const {
        return new PeripheralModelLearningState(*this);
    }
    // irq fork count
    void incirqfork_count(uint32_t pc) {
        ++irqfork_count[pc];
    }

    uint32_t getirqfork_count(uint32_t pc) {
        return irqfork_count[pc];
    }
    // phs cache
    // type flag
    void insert_all_rw_phs(uint32_t phaddr, uint32_t flag) {
        all_rw_phs[phaddr] = flag;
    }

    TypeFlagPeripheralMap get_all_rw_phs() {
        return all_rw_phs;
    }

    // type flag
    void insert_type_flag_phs(uint32_t phaddr, uint32_t flag) {
        type_flag_phs[phaddr] = flag;
    }

    TypeFlagPeripheralMap get_type_flag_phs() {
        return type_flag_phs;
    }

    uint32_t get_type_flag_ph_it(uint32_t phaddr) {
        return type_flag_phs[phaddr];
    }

    // t0
    void insert_t0_type_flag_phs(uint32_t phaddr, uint32_t flag) {
        t0_type_flag_phs[phaddr] = flag;
    }

    uint32_t get_t0_type_flag_ph_it(uint32_t phaddr) {
        return t0_type_flag_phs[phaddr];
    }

    void insert_t0_type_phs(uint32_t phaddr, uint32_t pc, uint64_t caller_fp_hash, NumPair no_value) {
        t0_type_phs[phaddr][pc] = std::make_pair(caller_fp_hash, no_value);
    }

    std::map<uint32_t, std::pair<uint64_t, NumPair>> get_t0_type_phs(uint32_t phaddr) {
        return t0_type_phs[phaddr];
    }

    // t1
    void insert_t1_type_phs(UniquePeripheral phc, uint64_t caller_fp_hash, NumPair no_value) {
        t1_type_phs[phc] = std::make_pair(caller_fp_hash, no_value);
    }

    T1BNPeripheralMap get_t1_type_phs() {
        return t1_type_phs;
    }

    uint32_t get_t1_type_ph_it(UniquePeripheral phc) {
        return t1_type_phs[phc].second.second;
    }

    void insert_lock_t1_type_flag(uint32_t phaddr, uint32_t flag) {
        lock_t1_type_flag[phaddr] = flag;
    }

    uint32_t get_lock_t1_type_flag(uint32_t phaddr) {
        return lock_t1_type_flag[phaddr];
    }

    // data t1 for first time store
    void insert_pdata_type_phs(UniquePeripheral phc, uint32_t value) {
        pdata_type_phs[phc] = value;
    }

    T1PeripheralMap get_pdata_type_phs() {
        return pdata_type_phs;
    }

    // pt1
    void insert_pt1_type_phs(UniquePeripheral phc, uint64_t caller_fp_hash, NumPair no_value) {
        pt1_type_phs[phc] = std::make_pair(caller_fp_hash, no_value);
    }

    T1BNPeripheralMap get_pt1_type_phs() {
        return pt1_type_phs;
    }

    uint32_t get_pt1_type_ph_it(UniquePeripheral phc) {
        return pt1_type_phs[phc].second.second;
    }

    void erase_pt1_type_ph_it(UniquePeripheral phc) {
        pt1_type_phs.erase(phc);
    }

    void insert_pt1_type_flag_phs(UniquePeripheral phc, uint32_t flag) {
        pt1_type_flag_phs[phc] = flag;
    }

    uint32_t get_pt1_type_flag_ph_it(UniquePeripheral phc) {
        return pt1_type_flag_phs[phc];
    }

    T1PeripheralMap get_pt1_type_flag_all_phs() {
        return pt1_type_flag_phs;
    }

    // t2
    void insert_t2_type_phs(UniquePeripheral phc, uint64_t caller_fp_hash, uint32_t value) {
        t2_type_phs[phc][caller_fp_hash] = value;
    }

    T2PeripheralMap get_t2_type_phs() {
        return t2_type_phs;
    }

    uint32_t get_t2_type_ph_it(UniquePeripheral phc, uint64_t caller_fp_hash) {
        return t2_type_phs[phc][caller_fp_hash];
    }

    CWMap get_t2_type_samepc_phs(UniquePeripheral phc) {
        return t2_type_phs[phc];
    }

    void erase_t2_type_phs(UniquePeripheral phc) {
        t2_type_phs.erase(phc);
    }

    void insert_t2_type_flag_phs(UniquePeripheral phc, uint32_t flag) {
        t2_type_flag_phs[phc] = flag;
    }

    uint32_t get_t2_type_flag_ph_it(UniquePeripheral phc) {
        return t2_type_flag_phs[phc];
    }

    void insert_pt2_type_flag_ph_it(UniquePeripheral phc, uint64_t caller_fp_hash, uint32_t flag) {
        pt2_type_flag_phs[phc][caller_fp_hash] = flag;
    }

    uint32_t get_pt2_type_flag_ph_it(UniquePeripheral phc, uint64_t caller_fp_hash) {
        return pt2_type_flag_phs[phc][caller_fp_hash];
    }

    // t3
    void insert_concrete_t3_flag(uint32_t phaddr, uint32_t flag) {
        concrete_t3_flag[phaddr] = flag;
    }

    uint32_t get_concrete_t3_flag(uint32_t phaddr) {
        return concrete_t3_flag[phaddr];
    }

    uint32_t get_t3_type_ph_size(uint32_t phaddr) {
        return t3_type_phs[phaddr].size();
    }

    void insert_t3_type_ph_back(uint32_t phaddr, uint32_t value) {
        if (find(t3_type_phs[phaddr].begin(), t3_type_phs[phaddr].end(), value) == t3_type_phs[phaddr].end())
            t3_type_phs[phaddr].push_back(value);
    }

    void push_t3_type_ph_back(uint32_t phaddr, uint32_t value) {
        t3_type_phs[phaddr].push_back(value);
    }

    T3PeripheralMap get_t3_type_phs() {
        return t3_type_phs;
    }

    void clear_t3_type_phs(uint32_t phaddr) {
        t3_type_phs[phaddr].clear();
    }

    void erase_t3_type_ph_it(uint32_t phaddr, uint32_t value) {
        std::deque<uint32_t>::iterator itun = std::find(t3_type_phs[phaddr].begin(), t3_type_phs[phaddr].end(), value);
        t3_type_phs[phaddr].erase(itun);
    }

    void pop_t3_type_ph_it(uint32_t phaddr) {
        t3_type_phs[phaddr].pop_front();
    }

    uint32_t get_t3_type_ph_it_front(uint32_t phaddr) {
        return t3_type_phs[phaddr].front();
    }

    uint32_t get_t3_type_ph_it_back(uint32_t phaddr) {
        return t3_type_phs[phaddr].back();
    }

    // irq flag for irqs
    void insert_irq_flag_phs(uint32_t phaddr, uint32_t flag) {
        type_irq_flag[phaddr] = flag;
    }

    uint32_t get_irq_flag_ph_it(uint32_t phaddr) {
        return type_irq_flag[phaddr];
    }

    // IRQS
    /* void insert_tirqs_type_phs(uint32_t irq_no, uint32_t phaddr, uint32_t pc, uint32_t value) { */
    // tirqs_type_phs[std::make_tuple(irq_no, phaddr, pc)].push_back(value);
    // }

    // std::deque<uint32_t> get_tirqs_type_phs(uint32_t irq_no, uint32_t phaddr, uint32_t pc) {
    // return tirqs_type_phs[std::make_tuple(irq_no, phaddr, pc)];
    /* } */

    /* TIRQSPeripheralMap get_tirqs_type_all_phs() { */
    // return tirqs_type_phs;
    /* } */

    // IRQC
    void insert_tirqc_type_phs(uint32_t irq_no, uint32_t phaddr, uint32_t crphaddr, uint32_t crvalue, uint32_t value) {
        if (find(tirqc_type_phs[std::make_pair(irq_no, phaddr)][crphaddr][crvalue].begin(),
                 tirqc_type_phs[std::make_pair(irq_no, phaddr)][crphaddr][crvalue].end(),
                 value) == tirqc_type_phs[std::make_pair(irq_no, phaddr)][crphaddr][crvalue].end())
            tirqc_type_phs[std::make_pair(irq_no, phaddr)][crphaddr][crvalue].push_back(value);
    }

    IRQCRMap get_tirqc_type_phs(uint32_t irq_no, uint32_t phaddr) {
        return tirqc_type_phs[std::make_pair(irq_no, phaddr)];
    }

    TIRQCPeripheralMap get_tirqc_type_all_phs() {
        return tirqc_type_phs;
    }

    // read and write phs
    void inc_readphs(uint32_t phaddr, uint32_t size) {
        read_phs[phaddr].first = size;
        read_phs[phaddr].second++;
    }

    uint64_t get_readphs_count(uint32_t phaddr) {
        return read_phs[phaddr].second;
    }

    uint32_t get_readphs_size(uint32_t phaddr) {
        return read_phs[phaddr].first;
    }

    void update_writeph(uint32_t phaddr, uint32_t value) {
        write_phs[phaddr] = value;
    }

    ReadPeripheralMap get_readphs() {
        return read_phs;
    }

    bool whether_write(uint32_t phaddr) {
        if (write_phs.count(phaddr) > 0) {
            return true;
        } else {
            return false;
        }
    }

    uint32_t get_writeph(uint32_t phaddr) {
        return write_phs[phaddr];
    }

    // last fork conds
    void insert_last_fork_cond(uint32_t pc, std::vector<uint32_t> cond_values) {
        last_fork_cond = std::make_pair(pc, cond_values);
    }

    std::pair<uint32_t, std::vector<uint32_t>> get_last_fork_cond() {
        return last_fork_cond;
    }

    // last fork phs interrupt
    void irq_insertlastfork_phs(uint32_t irq_num, UniquePeripheral phc, uint64_t ch_value, NumPair value_no) {
        irq_lastforkphs[irq_num][phc][ch_value] = value_no;
    }

    AllKnowledgeBaseMap irq_getlastfork_phs(uint32_t irq_num) {
        return irq_lastforkphs[irq_num];
    }

    void irq_clearlastfork_phs(uint32_t irq_num) {
        irq_lastforkphs[irq_num].clear();
    }

    // last fork phs
    void insertlastfork_phs(UniquePeripheral phc, uint64_t ch_value, NumPair value_no) {
        lastforkphs[phc][ch_value] = value_no;
    }

    AllKnowledgeBaseMap getlastfork_phs() {
        return lastforkphs;
    }

    void clearlastfork_phs() {
        lastforkphs.clear();
    }

    // update current irq peripherals
    void insert_current_irq_values(uint32_t phaddr, uint32_t value) {
        current_irq_phs_value.push_back(std::make_pair(phaddr, value));
    }

    void clear_current_irq_values() {
        current_irq_phs_value.clear();
    }

    std::deque<UniquePeripheral> get_current_irq_values() {
        return current_irq_phs_value;
    }

    // cache phs order by no
    void insert_cachephs(uint32_t phaddr, uint64_t no, uint32_t value) {
        allcache_phs[phaddr][no] = value;
    }

    NumMap get_cache_phs(uint32_t phaddr) {
        return allcache_phs[phaddr];
    }

    AllKnowledgeBaseNoMap get_all_cache_phs() {
        return allcache_phs;
    }

    // record all conditional phs
    void insert_condition_ph_it(uint32_t phaddr) {
        condition_phs[phaddr] = 1;
    }

    TypeFlagPeripheralMap get_condition_phs() {
        return condition_phs;
    }

    // record t3 max size map
    void insert_t3_size_ph_it(uint32_t phaddr, uint32_t size) {
        t3_size_map[phaddr] = size;
    }

    uint32_t get_t3_size_ph_it(uint32_t phaddr) {
        return t3_size_map[phaddr];
    }
    // update hash
    void insert_hashstack(uint32_t irq_no, uint64_t sum_hash) {
        hash_stack[irq_no].push_back(sum_hash);
    }

    void pop_hashstack(uint32_t irq_no) {
        hash_stack[irq_no].pop_back();
    }

    uint64_t get_current_hash(uint32_t irq_no) {
        if (hash_stack.find(irq_no) == hash_stack.end()) {
            return 0;
        } else {
            if (hash_stack[irq_no].size() == 0) {
                return 0;
            } else {
                return hash_stack[irq_no].back();
            }
        }
    }

    // update fork pc map in lastest read
    void inc_peripheral_fork_count(UniquePeripheral phc) {
        ph_forks_count[phc]++;
    }

    void clear_peripheral_fork_count(UniquePeripheral phc) {
        ph_forks_count[phc] = 0;
    }

    uint32_t get_peripheral_fork_count(UniquePeripheral phc) {
        return ph_forks_count[phc];
    }

    // update symbolic pc phs
    void insert_symbolicpc_ph_it(UniquePeripheral phc) {
        symbolicpc_phs[phc] = 1;
    }

    uint32_t get_symbolicpc_ph_it(UniquePeripheral phc) {
        return symbolicpc_phs[phc];
    }
    // update symbolic pc phs forking count
    void inc_symbolicpc_ph_count(UniquePeripheral phc) {
        symbolicpc_phs_fork_count[phc]++;
    }

    uint32_t get_symbolicpc_ph_count(UniquePeripheral phc) {
        return symbolicpc_phs_fork_count[phc];
    }

    // possible alive point count record
    void inc_alive_points_count(uint32_t pc) {
        alive_points_count[pc]++;
    }

    void clear_alive_points_count(uint32_t pc) {
        alive_points_count[pc] = 0;
    }

    uint32_t get_alive_points_count(uint32_t pc) {
        return alive_points_count[pc];
    }
};
}

void PeripheralModelLearning::initialize() {
    bool ok;

    if (!parseConfigIoT()) {
        getWarningsStream() << "Could not parse peripheral config\n";
        exit(-1);
    }

    round_count = 0;
    durationtime = 0;
    all_peripheral_no = 0;
    firmwareName = s2e()->getConfig()->getString(getConfigKey() + ".firmwareName", "x.elf");
    getWarningsStream() << "firmware name is " << firmwareName << "\n";
    enable_extended_irq_mode = s2e()->getConfig()->getBool(getConfigKey() + ".enableExtendedInterruptMode", false);
    auto_mode_switch = s2e()->getConfig()->getBool(getConfigKey() + ".autoModeSwitch", false);
    enable_fuzzing = s2e()->getConfig()->getBool(getConfigKey() + ".useFuzzer", false);
    t2_max_context = s2e()->getConfig()->getInt(getConfigKey() + ".maxT2Size", 8, &ok);
    t3_max_symbolic_count = s2e()->getConfig()->getInt(getConfigKey() + ".limitSymNum", 10, &ok);
    allow_new_phs = s2e()->getConfig()->getBool(getConfigKey() + ".allowNewPhs", true);
    if (!allow_new_phs) {
        getWarningsStream() << "Not allow new peripherals registers in fuzzing mode\n";
    }

    onARMFunctionConnection = s2e()->getPlugin<ARMFunctionMonitor>();
    onARMFunctionConnection->onARMFunctionCallEvent.connect(
        sigc::mem_fun(*this, &PeripheralModelLearning::onARMFunctionCall));
    onARMFunctionConnection->onARMFunctionReturnEvent.connect(
        sigc::mem_fun(*this, &PeripheralModelLearning::onARMFunctionReturn));
    onInvalidStateDectionConnection = s2e()->getPlugin<InvalidStatesDetection>();
    onInvalidStateDectionConnection->onInvalidStatesEvent.connect(
        sigc::mem_fun(*this, &PeripheralModelLearning::onInvalidStatesDetection));
    onInvalidStateDectionConnection->onLearningTerminationEvent.connect(
        sigc::mem_fun(*this, &PeripheralModelLearning::onLearningTerminationDetection));

    g_s2e_cache_mode = s2e()->getConfig()->getBool(getConfigKey() + ".useKnowledgeBase", false);
    if (g_s2e_cache_mode) {
        fileName = s2e()->getConfig()->getString(getConfigKey() + ".cacheFileName", "statename");
        if (!readKBfromFile(fileName)) {
            getWarningsStream() << "Could not read peripheral regs from cache file" << fileName << "\n";
            exit(-1);
        }
    } else {
        onInterruptExitonnection = s2e()->getCorePlugin()->onExceptionExit.connect(
            sigc::mem_fun(*this, &PeripheralModelLearning::onExceptionExit));
        onStateForkConnection =
            s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &PeripheralModelLearning::onFork));
        onStateSwitchConnection = s2e()->getCorePlugin()->onStateSwitch.connect(
            sigc::mem_fun(*this, &PeripheralModelLearning::onStateSwitch));
        onStateKillConnection =
            s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &PeripheralModelLearning::onStateKill));
        onStateForkDecideConnection = s2e()->getCorePlugin()->onStateForkDecide.connect(
            sigc::mem_fun(*this, &PeripheralModelLearning::onStateForkDecide));
        onSymbolicAddressConnection = s2e()->getCorePlugin()->onSymbolicAddress.connect(
            sigc::mem_fun(*this, &PeripheralModelLearning::onSymbolicAddress));
        // symbolic comparion test version
        // srand(0); // need to change for time in real mode
        // onStateForkConnection = s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this,
        // &PeripheralModelLearning::onForkTest));
        // onStateForkDecideConnection= s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this,
        // &PeripheralModelLearning::onStateForkDecideTest));
    }

    g_symbolicMemoryHook = SymbolicMemoryHook(symbhw_is_mmio_symbolic, symbhw_symbread, symbhw_symbwrite, this);

    start = time(NULL);
    // init rand() seed
    srand((unsigned) time(NULL));
}

template <typename T> bool PeripheralModelLearning::parseRangeList(ConfigFile *cfg, const std::string &key, T &result) {
    bool ok;

    int ranges = cfg->getListSize(key, &ok);
    if (!ok) {
        getWarningsStream() << "Could not parse ranges: " << key << "\n";
        return false;
    }

    for (int i = 0; i < ranges; ++i) {
        std::stringstream ss;
        ss << key << "[" << (i + 1) << "]";
        uint64_t start = cfg->getInt(ss.str() + "[1]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse start port: " << ss.str() + "[1]"
                                << "\n";
            return false;
        }

        uint64_t end = cfg->getInt(ss.str() + "[2]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse port range: " << ss.str() + "[2]"
                                << "\n";
            return false;
        }

        if (!(start <= end)) {
            getWarningsStream() << hexval(start) << " is greater than " << hexval(end) << "\n";
            return false;
        }

        result.push_back(std::make_pair(start, end));
    }

    return true;
}

bool PeripheralModelLearning::parseConfigIoT(void) {
    ConfigFile *cfg = s2e()->getConfig();
    auto keys = cfg->getListKeys(getConfigKey());

    SymbolicMmioRange m;

    // ARM MMIO range 0x40000000-0x60000000
    m.first = 0x40000000;
    m.second = 0x5fffffff;

    getDebugStream() << "Adding symbolic mmio range: " << hexval(m.first) << " - " << hexval(m.second) << "\n";
    m_mmio.push_back(m);

    return true;
}

template <typename T, typename U> inline bool PeripheralModelLearning::isSymbolic(T ports, U port) {
    for (auto &p : ports) {
        if (port >= p.first && port <= p.second) {
            return true;
        }
    }

    return false;
}

bool PeripheralModelLearning::isMmioSymbolic(uint64_t physAddr) {
    return isSymbolic(m_mmio, physAddr);
}

static void SymbHwGetConcolicVector(uint64_t in, unsigned size, ConcreteArray &out) {
    union {
        // XXX: assumes little endianness!
        uint64_t value;
        uint8_t array[8];
    };

    value = in;
    out.resize(size);
    for (unsigned i = 0; i < size; ++i) {
        out[i] = array[i];
    }
}

bool PeripheralModelLearning::getDREntryfromKB(std::string variablePeripheralName, uint32_t *type,
                                                    uint32_t *phaddr, uint32_t *size) {
    boost::smatch what;
    if (!boost::regex_match(variablePeripheralName, what, KBDRPeripheralRegEx)) {
        getWarningsStream() << "match false\n";
        return false;
    }

    if (what.size() != 5) {
        getWarningsStream() << "wrong size = " << what.size() << "\n";
        return false;
    }

    std::string modeStr = what[1];
    if (modeStr == "fuzz") {
        *type = T3;
    } else {
        getWarningsStream() << "Unrecognized DR Regs Format!\n";
        return false;
    }

    std::string peripheralAddressStr = what[2];
    std::string sizeStr = what[3];

    *phaddr = std::stoull(peripheralAddressStr.c_str(), NULL, 16);
    *size = std::stoull(sizeStr.c_str(), NULL, 16);

    return true;
}

bool PeripheralModelLearning::getIRQEntryfromKB(std::string variablePeripheralName, uint32_t *irq_no, uint32_t *type,
                                                uint32_t *phaddr, uint32_t *cr_phaddr, uint32_t *value,
                                                uint32_t *cr_value) {
    boost::smatch what;
    if (!boost::regex_match(variablePeripheralName, what, KBIRQPeripheralRegEx)) {
        getWarningsStream() << "match false\n";
        return false;
    }

    if (what.size() != 7) {
        getWarningsStream() << "wrong size = " << what.size() << "\n";
        return false;
    }

    std::string modeStr = what[1];
    if (modeStr == "tirqc") {
        *type = TIRQC;
    } else {
        getWarningsStream() << "Unrecognized Peripheral Regs!\n";
        return false;
    }

    std::string irqnoStr = what[2];
    std::string peripheralAddressStr = what[3];
    std::string crStr = what[4];
    std::string crvalueStr = what[5];
    std::string valueStr = what[6];

    *irq_no = std::stoull(irqnoStr.c_str(), NULL, 16);
    *cr_value = std::stoull(crvalueStr.c_str(), NULL, 16);
    *phaddr = std::stoull(peripheralAddressStr.c_str(), NULL, 16);
    *cr_phaddr = std::stoull(crStr.c_str(), NULL, 16);
    *value = std::stoull(valueStr.c_str(), NULL, 16);

    return true;
}

bool PeripheralModelLearning::getGeneralEntryfromKB(std::string variablePeripheralName, uint32_t *type,
                                                    uint32_t *phaddr, uint32_t *pc, uint32_t *value,
                                                    uint64_t *ch_value) {
    boost::smatch what;
    if (!boost::regex_match(variablePeripheralName, what, KBGeneralPeripheralRegEx)) {
        getWarningsStream() << "match false\n";
        return false;
    }

    if (what.size() != 6) {
        getWarningsStream() << "wrong size = " << what.size() << "\n";
        return false;
    }

    std::string modeStr = what[1];
    if (modeStr == "t0") {
        *type = T0;
    } else if (modeStr == "t1") {
        *type = T1;
    } else if (modeStr == "pt1" || modeStr == "dt1") {
        *type = PT1;
    } else if (modeStr == "t2") {
        *type = T2;
    } else if (modeStr == "t3") {
        *type = T3;
    } else if (modeStr == "tirqs") {
        *type = TIRQS;
    } else {
        getWarningsStream() << "Unrecognized Peripheral Regs!\n";
        return false;
    }

    std::string peripheralAddressStr = what[2];
    std::string pcStr = what[3];
    std::string cwStr = what[4];
    std::string valueStr = what[5];

    *ch_value = std::stoull(cwStr.c_str(), NULL, 16);
    *phaddr = std::stoull(peripheralAddressStr.c_str(), NULL, 16);
    *pc = std::stoull(pcStr.c_str(), NULL, 16);
    *value = std::stoull(valueStr.c_str(), NULL, 16);

    return true;
}

bool PeripheralModelLearning::readKBfromFile(std::string fileName) {
    std::ifstream fPHKB;
    std::string line;
    fPHKB.open(fileName, std::ios::in);
    if (!fPHKB) {
        getWarningsStream() << "Could not open cache peripheral knowledge base file: " << fileName << " \n";
        return false;
    }

    std::string peripheralcache;
    while (getline(fPHKB, peripheralcache)) {
        uint32_t type;
        uint32_t phaddr;
        uint32_t pc;
        uint32_t value;
        uint64_t cwirq_value;

        if (peripheralcache == "IRQCR") {
            break;
        }

        if (getGeneralEntryfromKB(peripheralcache, &type, &phaddr, &pc, &value, &cwirq_value)) {
            UniquePeripheral uniquePeripheral = std::make_pair(phaddr, pc);
            if (type == T0) {
                cache_type_flag_phs[phaddr] = T0;
            } else if (type == T1) {
                cache_type_flag_phs[phaddr] = T1;
                cache_t1_type_flag_phs[uniquePeripheral] = 1;
                cache_t1_type_phs[uniquePeripheral] = std::make_pair(cwirq_value, value);
            } else if (type == PT1) {
                cache_type_flag_phs[phaddr] = T1;
                cache_t1_type_flag_phs[uniquePeripheral] = 2;
                cache_pt1_type_phs[uniquePeripheral] = std::make_pair(cwirq_value, value);
            } else if (type == T2) {
                cache_type_flag_phs[phaddr] = T1;
                cache_t2_type_flag_phs[uniquePeripheral] = T2;
                cache_t2_type_phs[uniquePeripheral][cwirq_value] = value;
            } else if (type == T3) {
                cache_type_flag_phs[phaddr] = T3;
                cache_all_cache_phs[phaddr][cwirq_value] = value;
                cache_t3_type_phs_backup[phaddr].push_back(value);
                cache_t3_type_phs[phaddr].push_back(value);
                cache_dr_type_size[phaddr] = pc; // pc_pos is size for t3
            } else if (type == TIRQS) {
                cache_type_flag_phs[phaddr] = T1;
                cache_type_irqs_flag[std::make_tuple(cwirq_value, phaddr, pc)] = 1;
                cache_tirqs_type_phs[std::make_tuple(cwirq_value, phaddr, pc)].push_back(value);
            } else {
                getWarningsStream() << "Unrecognized perpherial\n";
            }
            valid_phs.push_back(phaddr);
        } else {
            return false;
        }
    }
    std::sort(valid_phs.begin(), valid_phs.end());
    valid_phs.erase(std::unique(valid_phs.begin(), valid_phs.end()), valid_phs.end());

    std::string peripheral_irqcr_cache;
    while (getline(fPHKB, peripheral_irqcr_cache)) {
        uint32_t type;
        uint32_t phaddr;
        uint32_t cr_phaddr;
        uint32_t value;
        uint32_t cr_value;
        uint32_t irq_no;

        if (peripheral_irqcr_cache == "DefaultDataRegs") {
            break;
        }

        if (getIRQEntryfromKB(peripheral_irqcr_cache, &irq_no, &type, &phaddr, &cr_phaddr, &value, &cr_value)) {
            if (type == TIRQC) {
                cache_type_flag_phs[phaddr] = T1;
                cache_type_irqc_flag[std::make_pair(irq_no, phaddr)] = 2;
                cache_tirqc_type_phs[std::make_pair(irq_no, phaddr)][cr_phaddr][cr_value].push_back(value);
            } else {
                getWarningsStream() << "unrecognized perpherial\n";
            }
        } else {
            return false;
        }
    }

    std::string peripheral_dr_cache;
    while (getline(fPHKB, peripheral_dr_cache)) {
        uint32_t type;
        uint32_t phaddr;
        uint32_t size;

        if (peripheral_dr_cache == "CandidateDataRegs") {
            break;
        }

        if (getDREntryfromKB(peripheral_dr_cache, &type, &phaddr, &size)) {
            if (cache_type_flag_phs[phaddr] != T3) {
                cache_type_flag_phs[phaddr] = T3;
                cache_dr_type_size[phaddr] = size;
            } else {
                if (cache_t3_type_phs[phaddr].size() == 1) { //only one item no need for replay leave for fuzzing
                    cache_t3_type_phs[phaddr].pop_front();
                }
            }
        } else {
            return false;
        }
    }

    return true;
}

struct CmpByCount {
    bool operator()(const ReadTUPLE &ph1, const ReadTUPLE &ph2) {
        return ph1.second.second > ph2.second.second;
    }
};

struct CmpByNo {
    bool operator()(const std::pair<uint64_t, uint32_t> &ph1, const std::pair<uint64_t, uint32_t> &ph2) {
        return ph1.first < ph2.first;
    }
};

void PeripheralModelLearning::writeTIRQPeripheralstoKB(S2EExecutionState *state, std::ofstream &fPHKB) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);

    TIRQCPeripheralMap tirqc_type_phs = plgState->get_tirqc_type_all_phs();
    // tirq cache
    TIRQPeripheralMapFlag empty_tirqc_flag;
    for (auto itpossirqs : possible_irq_values) {
        if (plgState->get_type_flag_ph_it(std::get<1>(itpossirqs.first)) == T1) {
            if (plgState->get_irq_flag_ph_it(std::get<1>(itpossirqs.first)) == 1) {
                for (auto irqs_value : itpossirqs.second) {
                    fPHKB << "tirqs_" << hexval(std::get<1>(itpossirqs.first)) << "_"
                          << hexval(std::get<2>(itpossirqs.first)) << "_" << hexval(std::get<0>(itpossirqs.first))
                          << "_" << hexval(irqs_value) << std::endl;
                }
            } else if (plgState->get_irq_flag_ph_it(std::get<1>(itpossirqs.first)) == 2 &&
                       tirqc_type_phs[std::make_pair(std::get<0>(itpossirqs.first), std::get<1>(itpossirqs.first))]
                               .size() == 0) {
                empty_tirqc_flag[std::make_pair(std::get<0>(itpossirqs.first), std::get<1>(itpossirqs.first))] = 1;
            }
        }
    }

    fPHKB << "IRQCR" << std::endl;

    for (auto ittirqc : tirqc_type_phs) {
        if (plgState->get_type_flag_ph_it(ittirqc.first.second) == T1) {
            if (plgState->get_irq_flag_ph_it(ittirqc.first.second) == 2) {
                for (auto itcrs : ittirqc.second) {
                    for (auto itcr : itcrs.second) {
                        for (auto itv : itcr.second) {
                            fPHKB << "tirqc_" << hexval(ittirqc.first.first) << "_" << hexval(ittirqc.first.second)
                                  << "_" << hexval(itcrs.first) << "_" << hexval(itcr.first) << "_" << hexval(itv)
                                  << std::endl;
                        }
                    }
                }
            }
        }
    }

    for (auto irq_no : empty_tirqc_flag) {
        if (irq_no.second == 1) {
            for (auto irq_sr : irq_srs[irq_no.first.first]) {
                if (tirqc_type_phs[irq_no.first].size() == 0) {
                    for (auto irq_cr : irq_crs[irq_no.first.second]) {
                        fPHKB << "ptirqc_" << hexval(irq_no.first.first) << "_" << hexval(irq_sr) << "_"
                              << hexval(irq_cr.first) << "_" << hexval(irq_cr.second) << "_"
                              << "0x0" << std::endl;
                        break;
                    }
                }
            }
        }
    }
}

void PeripheralModelLearning::identifyDataPeripheralRegs(S2EExecutionState *state, std::ofstream &fPHKB) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);

    ReadPeripheralMap read_cache_phs = plgState->get_readphs();
    ReadPeripheralMap read_cache_data_phs;
    TypeFlagPeripheralMap type_flag_phs = plgState->get_type_flag_phs();

    ReadPeripheralMap::iterator it;
    it = read_cache_phs.begin();
    while (it != read_cache_phs.end()) {
        if (type_flag_phs[it->first] == T3) {
            read_cache_data_phs[it->first] = it->second;
            read_cache_phs.erase(it++);
            continue;
        } else if (type_flag_phs[it->first] == T1) {
            if (irq_data_phs[it->first] == 2) { // data regs in irq
                read_cache_data_phs[it->first] = it->second;
                read_cache_phs.erase(it++);
                continue;
            } else if (irq_data_phs[it->first] == 1) { // status and control regs in irq
                read_cache_phs.erase(it++);
                continue;
            }
            if (plgState->get_lock_t1_type_flag(it->first) == 1) {
                read_cache_phs.erase(it++); // remove t1 type
                continue;
            }
        } else {
            read_cache_phs.erase(it++);
            continue;
        }

        it++;
    }

    std::vector<ReadTUPLE> fuzz_candidate_phs;
    std::vector<ReadTUPLE> fuzz_data_phs;

    for (auto &it : read_cache_data_phs) {
        fuzz_data_phs.push_back(std::make_pair(it.first, it.second));
    }

    fPHKB << "DefaultDataRegs" << std::endl;
    std::sort(fuzz_data_phs.begin(), fuzz_data_phs.end(), CmpByCount());
    for (auto itd : fuzz_data_phs) {
        fPHKB << "fuzz_" << hexval(itd.first) << "_" << hexval(itd.second.first) << "_" << hexval(itd.second.second)
              << std::endl;
    }

    fPHKB << "CandidateDataRegs" << std::endl;
    for (auto &it : read_cache_phs) {
        fuzz_candidate_phs.push_back(std::make_pair(it.first, it.second));
    }
    std::sort(fuzz_candidate_phs.begin(), fuzz_candidate_phs.end(), CmpByCount());
    for (auto itc : fuzz_candidate_phs) {
        fPHKB << "fuzzc_" << hexval(itc.first) << "_" << hexval(itc.second.first) << "_" << hexval(itc.second.second)
              << std::endl;
    }
}

klee::ref<klee::Expr> PeripheralModelLearning::onLearningMode(S2EExecutionState *state, SymbolicHardwareAccessType type,
                                                              uint64_t address, unsigned size, uint64_t concreteValue) {

    uint32_t phaddr = address;
    uint32_t pc = state->regs()->getPc();
    std::stringstream ss;
    switch (type) {
        case SYMB_MMIO:
            ss << "iommuread_";
            break;
        case SYMB_DMA:
            ss << "dmaread_";
            break;
        case SYMB_PORT:
            ss << "portread_";
            break;
    }

    ss << hexval(address) << "@" << hexval(pc);

    // record all read phs
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);
    plgState->inc_readphs(phaddr, size);
    plgState->insert_all_rw_phs(phaddr, 1);

    uint64_t LSB = ((uint64_t) 1 << (size * 8));
    uint32_t value;

    if (plgState->get_symbolicpc_ph_it(UniquePeripheral(phaddr, pc)) == 1) {
        if (plgState->get_type_flag_ph_it(phaddr) == T0) {
            getWarningsStream() << " In learning mode, reading T0 usa as symbolic pc with phaddr = " << hexval(phaddr)
                                << " pc = " << hexval(pc) << " return value set as written"
                                << "\n";
            value = plgState->get_writeph(phaddr) & (LSB - 1);
            return klee::ConstantExpr::create(value, size * 8);
        } else {
            if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) {
                getWarningsStream() << " In learning mode, reading reg usa as symbolic pc with phaddr = "
                                    << hexval(phaddr) << " pc = " << hexval(pc) << " return value in external interrupt"
                                    << "\n";
            } else {
                getWarningsStream() << " In learning mode, reading reg use as symbolic pc with phaddr = "
                                    << hexval(phaddr) << " pc = " << hexval(pc) << " return value set as zero"
                                    << "\n";
                return klee::ConstantExpr::create(0x0, size * 8);
            }
        }
    }

    uint64_t sum_hash = 0x0;
    if (state->regs()->getInterruptFlag()) {
        sum_hash = plgState->get_current_hash(state->regs()->getExceptionIndex());
    } else {
        sum_hash = plgState->get_current_hash(0);
    }
    ss << "_" << hexval(sum_hash);

    plgState->insert_t0_type_flag_phs(phaddr, 1);
    all_peripheral_no++;

    getWarningsStream(state) << ss.str() << " size " << hexval(size) << " sum_hash = " << hexval(sum_hash)
                             << " reading times = " << plgState->get_readphs_count(phaddr)
                             << " peripheral no = " << all_peripheral_no - 1 << "\n";

    // first find peripheral type
    TypeFlagPeripheralMap type_flag_phs = plgState->get_type_flag_phs();
    TypeFlagPeripheralMap::iterator itf = type_flag_phs.find(phaddr);
    if (itf == type_flag_phs.end()) {
        ConcreteArray concolicValue;
        if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) {
            if (find(irq_srs[state->regs()->getExceptionIndex()].begin(),
                     irq_srs[state->regs()->getExceptionIndex()].end(),
                     phaddr) == irq_srs[state->regs()->getExceptionIndex()].end()) {
                irq_srs[state->regs()->getExceptionIndex()].push_back(phaddr);
            }
            irq_data_phs[phaddr] = 2;
            possible_irq_srs[std::make_pair(phaddr, pc)] = state->regs()->getExceptionIndex();
        }
        getDebugStream() << " First time read ph addr = " << hexval(phaddr) << " as T1 type\n";
        plgState->insert_pt1_type_flag_phs(UniquePeripheral(phaddr, pc), 1);
        plgState->insert_type_flag_phs(phaddr, T1);
        SymbHwGetConcolicVector(0x0, size, concolicValue);
        plgState->insert_cachephs(phaddr, all_peripheral_no - 1, 0);
        return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
    }

    if (enable_fuzzing) {
        bool fuzzOk = false;
        uint32_t fuzz_value;
        uint32_t fuzz_size;

        if (plgState->get_type_flag_ph_it(phaddr) == T3) {
            fuzzOk = true;
            fuzz_size = cache_dr_type_size[phaddr];
        }

        onFuzzingInput.emit(state, (PeripheralRegisterType) itf->second, phaddr, 0, &fuzz_size, &fuzz_value, &fuzzOk);

        if (fuzzOk) {
            getDebugStream() << " In learning mode, reading data from fuzzing input addr = " << hexval(phaddr)
                             << " pc = " << hexval(pc) << " return value set as zero"
                             << " size = " << size << "\n";
            return klee::ConstantExpr::create(0x0, size * 8);
        }
    }

    switch (plgState->get_type_flag_ph_it(phaddr)) {
        case T0: {
            getWarningsStream() << " T0 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                << " value = " << hexval(plgState->get_writeph(phaddr)) << " size = " << hexval(size)
                                << "\n";
            if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) {
                irq_crs[state->regs()->getExceptionIndex()][phaddr] = plgState->get_writeph(phaddr);
            }
            plgState->insert_pt1_type_flag_phs(UniquePeripheral(phaddr, pc), 1);
            plgState->insert_pdata_type_phs(std::make_pair(phaddr, pc), plgState->get_writeph(phaddr));
            plgState->insert_t0_type_phs(phaddr, pc, sum_hash,
                                         std::make_pair(all_peripheral_no, plgState->get_writeph(phaddr)));
            plgState->insert_cachephs(phaddr, all_peripheral_no - 1, plgState->get_writeph(phaddr));
            value = plgState->get_writeph(phaddr) & (LSB - 1);
            if (plgState->get_readphs_count(phaddr) > 200 && !state->regs()->getInterruptFlag() && !enable_fuzzing) {
                all_peripheral_no--;
                return klee::ConstantExpr::create(value, size * 8);
            }
            ConcreteArray concolicValue;
            SymbHwGetConcolicVector(value, size, concolicValue);
            return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
        }
        case T1: {
            if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) { // irq mode
                if (irq_data_phs[phaddr] != 1) { // mark data reg in external irq
                    irq_data_phs[phaddr] = 2;
                }
                uint32_t IRQS_value = 0;
                ConcreteArray concolicValue;
                plgState->insert_pt1_type_flag_phs(UniquePeripheral(phaddr, pc), 2);
                if (find(irq_srs[state->regs()->getExceptionIndex()].begin(),
                         irq_srs[state->regs()->getExceptionIndex()].end(),
                         phaddr) == irq_srs[state->regs()->getExceptionIndex()].end()) {
                    irq_srs[state->regs()->getExceptionIndex()].push_back(phaddr);
                }
                IRQPhTuple uniqueirqsphs = std::make_tuple(state->regs()->getExceptionIndex(), phaddr, pc);
                if (possible_irq_values[uniqueirqsphs].size() > 0) {
                    possible_irq_srs[std::make_pair(phaddr, pc)] = state->regs()->getExceptionIndex();
                    uint32_t rand_no = 0;
                    if (possible_irq_values[uniqueirqsphs].size() > 1) {
                        rand_no = rand() % possible_irq_values[uniqueirqsphs].size();
                        IRQS_value = possible_irq_values[uniqueirqsphs][rand_no] & (LSB - 1);
                        if (IRQS_value == 0) {
                            rand_no = rand() % possible_irq_values[uniqueirqsphs].size();
                            IRQS_value = possible_irq_values[uniqueirqsphs][rand_no] & (LSB - 1);
                        }
                        // before termination, we need to go though all possible irq values
                        while (find(already_used_irq_values[uniqueirqsphs].begin(),
                                    already_used_irq_values[uniqueirqsphs].end(),
                                    IRQS_value) != already_used_irq_values[uniqueirqsphs].end()) {
                            rand_no = rand() % possible_irq_values[uniqueirqsphs].size();
                            IRQS_value = possible_irq_values[uniqueirqsphs][rand_no] & (LSB - 1);
                            if (already_used_irq_values[uniqueirqsphs].size() ==
                                possible_irq_values[uniqueirqsphs].size()) {
                                break;
                            }
                        }
                    } else {
                        IRQS_value = possible_irq_values[uniqueirqsphs][rand_no] & (LSB - 1);
                    }
                    if (find(already_used_irq_values[uniqueirqsphs].begin(),
                             already_used_irq_values[uniqueirqsphs].end(),
                             IRQS_value) == already_used_irq_values[uniqueirqsphs].end()) {
                        already_used_irq_values[uniqueirqsphs].push_back(IRQS_value);
                    }
                    std::deque<uint32_t>::iterator itirq_rand =
                        std::find(possible_irq_values[uniqueirqsphs].begin(), possible_irq_values[uniqueirqsphs].end(),
                                  IRQS_value);
                    possible_irq_values[uniqueirqsphs].erase(itirq_rand);
                    possible_irq_values[uniqueirqsphs].push_front(IRQS_value);
                } else {
                    possible_irq_srs[std::make_pair(phaddr, pc)] = state->regs()->getExceptionIndex();
                }
                plgState->insert_current_irq_values(phaddr, IRQS_value);
                getDebugStream() << " IRQ T1(SR) type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                 << " value = " << hexval(IRQS_value)
                                 << " possible size = " << possible_irq_values[uniqueirqsphs].size()
                                 << " already size = " << already_used_irq_values[uniqueirqsphs].size() << "\n";
                if (already_used_irq_values[uniqueirqsphs].size() == possible_irq_values[uniqueirqsphs].size() &&
                    possible_irq_values[uniqueirqsphs].size() != 0) {
                    return klee::ConstantExpr::create(IRQS_value, size * 8);
                } else if (plgState->get_symbolicpc_ph_it(UniquePeripheral(phaddr, pc)) == 1) {
                    return klee::ConstantExpr::create(IRQS_value, size * 8);
                } else {
                    SymbHwGetConcolicVector(IRQS_value, size, concolicValue);
                    return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
                }
            } else { // normal mode
                if (plgState->get_t2_type_flag_ph_it(UniquePeripheral(phaddr, pc)) == T2) {
                    CWMap itt2s = plgState->get_t2_type_samepc_phs(UniquePeripheral(phaddr, pc));
                    CWMap::iterator itt2 = itt2s.find(sum_hash);
                    if (itt2 != itt2s.end()) {
                        value = plgState->get_t2_type_ph_it(UniquePeripheral(phaddr, pc), sum_hash) & (LSB - 1);
                        getDebugStream() << " T2 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                         << " value = " << hexval(value) << " size = " << hexval(size) << "\n";
                        if (plgState->get_pt2_type_flag_ph_it(UniquePeripheral(phaddr, pc), sum_hash) == 1) {
                            plgState->insert_pt2_type_flag_ph_it(UniquePeripheral(phaddr, pc), sum_hash, 2);
                        }
                        if (plgState->get_readphs_count(phaddr) > 100) {
                            all_peripheral_no--;
                            return klee::ConstantExpr::create(value, size * 8);
                        } else {
                            ConcreteArray concolicValue;
                            SymbHwGetConcolicVector(value, size, concolicValue);
                            return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
                        }
                    } else {
                        plgState->insert_pt2_type_flag_ph_it(UniquePeripheral(phaddr, pc), sum_hash, 1);
                        ConcreteArray concolicValue;
                        SymbHwGetConcolicVector(0x0, size, concolicValue);
                        return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
                    }
                } else { // real T1
                    T1BNPeripheralMap t1_type_phs = plgState->get_t1_type_phs();
                    T1BNPeripheralMap::iterator itt1 = t1_type_phs.find(UniquePeripheral(phaddr, pc));
                    if (itt1 != t1_type_phs.end()) {
                        value = plgState->get_t1_type_ph_it(UniquePeripheral(phaddr, pc));
                        plgState->insert_pt1_type_flag_phs(UniquePeripheral(phaddr, pc), 2);
                        getDebugStream() << " T1 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                         << " value = " << hexval(value) << "\n";
                        if (plgState->get_readphs_count(phaddr) > 200) {
                            all_peripheral_no--;
                            return klee::ConstantExpr::create(value, size * 8);
                        } else {
                            plgState->insert_cachephs(phaddr, all_peripheral_no - 1, value);
                            ConcreteArray concolicValue;
                            SymbHwGetConcolicVector(value, size, concolicValue);
                            return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
                        }
                    } else {
                        T1BNPeripheralMap pt1_type_phs = plgState->get_pt1_type_phs();
                        T1BNPeripheralMap::iterator itpt1 = pt1_type_phs.find(UniquePeripheral(phaddr, pc));
                        if (itpt1 == pt1_type_phs.end()) {
                            plgState->insert_cachephs(phaddr, all_peripheral_no - 1, 0);
                            ConcreteArray concolicValue;
                            plgState->insert_pt1_type_flag_phs(UniquePeripheral(phaddr, pc), 1);
                            SymbHwGetConcolicVector(0x0, size, concolicValue);
                            return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
                        } else {
                            plgState->insert_pt1_type_flag_phs(UniquePeripheral(phaddr, pc), 2);
                            value = plgState->get_pt1_type_ph_it(UniquePeripheral(phaddr, pc));
                            if (plgState->get_readphs_count(phaddr) > 200) {
                                getDebugStream() << " CON PT1 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                                 << " value = " << hexval(value) << " size = " << hexval(size) << "\n";
                                all_peripheral_no--;
                                return klee::ConstantExpr::create(value, size * 8);
                            } else {
                                getDebugStream() << " Sym PT1 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                                 << " value = " << hexval(value) << " size = " << hexval(size) << "\n";
                                plgState->insert_cachephs(phaddr, all_peripheral_no - 1, value);
                                ConcreteArray concolicValue;
                                SymbHwGetConcolicVector(value, size, concolicValue);
                                return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
                            }
                        }
                    }
                }
            }
        }
        case T3: {
            if (plgState->get_concrete_t3_flag(phaddr) == 1) {
                value = plgState->get_t3_type_ph_it_front(phaddr);
                plgState->pop_t3_type_ph_it(phaddr);
                // uint32_t rand_loc = rand() % 2;
                // if (rand_loc) {
                plgState->push_t3_type_ph_back(phaddr, value);
                //} else {
                //    plgState->insert_t3_type_ph_front(phaddr, value);
                //}
                all_peripheral_no--;
                getDebugStream() << " value come from T3 loop2 type pc = " << hexval(pc) << " value = " << hexval(value)
                                 << "\n";
                return klee::ConstantExpr::create(value, size * 8);
            } else if (plgState->get_t3_type_ph_size(phaddr) > 5 ||
                       plgState->get_readphs_count(phaddr) >= t3_max_symbolic_count) {
                std::vector<std::pair<uint64_t, uint32_t>> ituncaches;
                ituncaches.clear();
                for (auto &itun : plgState->get_cache_phs(phaddr)) {
                    ituncaches.push_back(std::make_pair(itun.first, itun.second));
                }
                std::sort(ituncaches.begin(), ituncaches.end(), CmpByNo());
                plgState->clear_t3_type_phs(phaddr);
                for (auto ituncache : ituncaches) {
                    plgState->push_t3_type_ph_back(phaddr, ituncache.second);
                    getDebugStream() << " T3 loop1 to loop2 type phaddr = " << hexval(phaddr)
                                     << " value = " << hexval(ituncache.second) << " no = " << hexval(ituncache.first)
                                     << "\n";
                }
                plgState->insert_concrete_t3_flag(phaddr, 1);
                plgState->insert_t3_size_ph_it(phaddr, plgState->get_readphs_count(phaddr));
                value = plgState->get_t3_type_ph_it_front(phaddr);
                plgState->pop_t3_type_ph_it(phaddr);
                plgState->push_t3_type_ph_back(phaddr, value);
                all_peripheral_no--;
                getDebugStream() << " value come from T3 loop1 type phaddr = " << hexval(phaddr)
                                 << " pc = " << hexval(pc) << " value = " << hexval(value) << "\n";
                return klee::ConstantExpr::create(value, size * 8);
            } else {
                plgState->insert_cachephs(phaddr, all_peripheral_no - 1, 0);
                plgState->insert_t3_size_ph_it(phaddr, plgState->get_readphs_count(phaddr));
                getDebugStream() << " value come from T3 loop0 type phaddr = " << hexval(phaddr)
                                 << " pc = " << hexval(pc) << " no = " << all_peripheral_no - 1 << "\n";
                ConcreteArray concolicValue;
                SymbHwGetConcolicVector(plgState->get_t3_type_ph_it_back(phaddr), size, concolicValue);
                return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
            }
        }
        default: {
            getWarningsStream() << "ERROR Type of Peripheral\n";
            exit(-1);
        }
    }
}

klee::ref<klee::Expr> PeripheralModelLearning::onFuzzingMode(S2EExecutionState *state, SymbolicHardwareAccessType type,
                                                             uint64_t address, unsigned size, uint64_t concreteValue) {

    uint32_t phaddr = address;
    uint32_t pc = state->regs()->getPc();
    std::stringstream ss;
    switch (type) {
        case SYMB_MMIO:
            ss << "iommuread_";
            break;
        case SYMB_DMA:
            ss << "dmaread_";
            break;
        case SYMB_PORT:
            ss << "portread_";
            break;
    }

    ss << hexval(address) << "@" << hexval(pc);

    // record all read phs
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);
    plgState->inc_readphs(phaddr, size);

    TypeFlagPeripheralMap::iterator itf = cache_type_flag_phs.find(phaddr);
    if (itf == cache_type_flag_phs.end()) {
        std::vector<uint32_t>::iterator itph = find(valid_phs.begin(), valid_phs.end(), phaddr);
        if (itph == valid_phs.end() && !allow_new_phs) {
            getWarningsStream() << " date type concrete value from invalid ph addr = " << hexval(phaddr)
                                << " pc = " << hexval(pc) << " value = " << 0x0 << "\n";
            onInvalidPHs.emit(state, phaddr);
            return klee::ConstantExpr::create(0x0, size * 8);
        }
        return switchModefromFtoL(state, ss.str(), phaddr, size, concreteValue);
    }

    bool fuzzOk = false;
    if (enable_fuzzing) {
        uint32_t fuzz_value;
        uint32_t fuzz_size;

        if (itf->second == T3) {
            fuzzOk = true;
            fuzz_size = cache_dr_type_size[phaddr];
            onFuzzingInput.emit(state, (PeripheralRegisterType) itf->second, phaddr,
                                cache_t3_type_phs[itf->first].size(), &fuzz_size, &fuzz_value, &fuzzOk);
            if (cache_t3_type_phs[itf->first].size() == 0) {
                getDebugStream() << " data from fuzzing input addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                 << " value = " << hexval(fuzz_value) << " size = " << size << "\n";
                uint64_t fuzz_LSB = ((uint64_t) 1 << (fuzz_size * 8));
                fuzz_value = fuzz_value & (fuzz_LSB - 1);
                return klee::ConstantExpr::create(fuzz_value, size * 8);
            }
        } else {
            onFuzzingInput.emit(state, (PeripheralRegisterType) itf->second, phaddr, 0, &fuzz_size, &fuzz_value,
                                &fuzzOk);
            if (fuzzOk) {
                getDebugStream() << " data from fuzzing input addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                 << " value = " << hexval(fuzz_value) << " size = " << size << "\n";
                uint64_t fuzz_LSB = ((uint64_t) 1 << (fuzz_size * 8));
                fuzz_value = fuzz_value & (fuzz_LSB - 1);
                return klee::ConstantExpr::create(fuzz_value, size * 8);
            }
        }
    }

    uint64_t sum_hash;
    if (state->regs()->getInterruptFlag()) {
        sum_hash = plgState->get_current_hash(state->regs()->getExceptionIndex());
    } else {
        sum_hash = plgState->get_current_hash(0);
    }

    uint64_t LSB = ((uint64_t) 1 << (size * 8));
    uint32_t value;
    getDebugStream() << " reading addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                     << " hash  = " << hexval(sum_hash) << " size =" << hexval(size) << "\n";

    switch (itf->second) {
        case T0: {
            if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) {
                irq_crs[state->regs()->getExceptionIndex()][phaddr] = plgState->get_writeph(phaddr);
            }
            value = plgState->get_writeph(phaddr);
            if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) {
                irq_crs[state->regs()->getExceptionIndex()][phaddr] = plgState->get_writeph(phaddr);
            }
            value = value & (LSB - 1);
            getDebugStream() << " T0 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                             << " value = " << hexval(value) << " size =" << hexval(size) << "\n";
            return klee::ConstantExpr::create(value, size * 8);
        }
        case T1: {
            if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) { // external irq handle
                if (find(irq_srs[state->regs()->getExceptionIndex()].begin(),
                         irq_srs[state->regs()->getExceptionIndex()].end(),
                         phaddr) == irq_srs[state->regs()->getExceptionIndex()].end()) {
                    irq_srs[state->regs()->getExceptionIndex()].push_back(phaddr);
                }
                possible_irq_srs[std::make_pair(phaddr, pc)] = state->regs()->getExceptionIndex();
                IRQPhTuple uniqueirqsphs = std::make_tuple(state->regs()->getExceptionIndex(), itf->first, pc);
                if (cache_t1_type_flag_phs[UniquePeripheral(phaddr, pc)] == 1) {
                    value = cache_t1_type_phs[UniquePeripheral(phaddr, pc)].second & (LSB - 1);
                    getDebugStream() << " TIRQ T1 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                     << " value = " << hexval(value) << " size =" << hexval(size) << "\n";
                    return klee::ConstantExpr::create(value, size * 8);
                } else if (cache_type_irqs_flag[uniqueirqsphs] == 1) {
                    uint32_t rand_no = rand() % cache_tirqs_type_phs[uniqueirqsphs].size();
                    value = cache_tirqs_type_phs[uniqueirqsphs][rand_no] & (LSB - 1);
                    std::deque<uint32_t>::iterator itirq_rand = std::find(
                        cache_tirqs_type_phs[uniqueirqsphs].begin(), cache_tirqs_type_phs[uniqueirqsphs].end(), value);
                    cache_tirqs_type_phs[uniqueirqsphs].erase(itirq_rand);
                    cache_tirqs_type_phs[uniqueirqsphs].push_back(value); // refill to t3 cache for next fuzzing
                    getDebugStream() << " TIRQS type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                     << " value = " << hexval(value) << " size =" << hexval(size) << "\n";
                    if (phaddr == 0x50000020) {
                        getWarningsStream() << " TIRQS type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                            << " value = " << hexval(value) << " size =" << hexval(size) << "\n";
                    }
                    return klee::ConstantExpr::create(value, size * 8);
                } else if (cache_type_irqc_flag[std::make_pair(state->regs()->getExceptionIndex(), itf->first)] == 2) {
                    for (auto cache_tirqc_phs :
                         cache_tirqc_type_phs[std::make_pair(state->regs()->getExceptionIndex(), itf->first)]) {
                        if (cache_tirqc_phs.second.count(plgState->get_writeph(cache_tirqc_phs.first)) > 0) {
                            uint32_t rand_no =
                                rand() % cache_tirqc_phs.second[plgState->get_writeph(cache_tirqc_phs.first)].size();
                            value = cache_tirqc_phs.second[plgState->get_writeph(cache_tirqc_phs.first)][rand_no] &
                                    (LSB - 1);
                            std::deque<uint32_t>::iterator itirq_rand = std::find(
                                cache_tirqc_phs.second[plgState->get_writeph(cache_tirqc_phs.first)].begin(),
                                cache_tirqc_phs.second[plgState->get_writeph(cache_tirqc_phs.first)].end(), value);
                            cache_tirqc_phs.second[plgState->get_writeph(cache_tirqc_phs.first)].erase(itirq_rand);
                            cache_tirqc_phs.second[plgState->get_writeph(cache_tirqc_phs.first)].push_back(
                                value); // refill to t3 cache for next fuzzing
                            getDebugStream()
                                << " TIRQC type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                << " value = " << hexval(value) << " cr phaddr = " << hexval(cache_tirqc_phs.first)
                                << " cr value =" << hexval(plgState->get_writeph(cache_tirqc_phs.first)) << " size = "
                                << cache_tirqc_phs.second[plgState->get_writeph(cache_tirqc_phs.first)].size() << "\n";
                            return klee::ConstantExpr::create(value, size * 8);
                        } else if (plgState->get_writeph(cache_tirqc_phs.first) == 0) {
                            getDebugStream()
                                << " TIRQC type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc) << " value = 0"
                                << " cr phaddr = " << hexval(cache_tirqc_phs.first)
                                << " cr value = " << hexval(plgState->get_writeph(cache_tirqc_phs.first)) << "\n";
                            return klee::ConstantExpr::create(0x0, size * 8);
                        } else {
                            for (auto cr_values : cache_tirqc_phs.second) {
                                for (auto sr_value : cr_values.second) {
                                    if (sr_value & plgState->get_writeph(cache_tirqc_phs.first)) {
                                        plgState->insert_current_irq_values(phaddr, sr_value);
                                        getWarningsStream()
                                            << " Change mode due to TIRQC type ph addr = " << hexval(phaddr)
                                            << " pc = " << hexval(pc) << " sr value = " << hexval(sr_value)
                                            << " cr phaddr = " << hexval(cache_tirqc_phs.first)
                                            << " cr value = " << hexval(plgState->get_writeph(cache_tirqc_phs.first))
                                            << "\n";
                                        concreteValue = sr_value & (LSB - 1);
                                        return switchModefromFtoL(state, ss.str(), phaddr, size, concreteValue);
                                    }
                                }
                            }
                            getWarningsStream()
                                << " Change mode due to TIRQC type ph addr = " << hexval(phaddr)
                                << " pc = " << hexval(pc) << " sr value = " << 0x0
                                << " cr phaddr = " << hexval(cache_tirqc_phs.first)
                                << " cr value = " << hexval(plgState->get_writeph(cache_tirqc_phs.first)) << "\n";
                            return switchModefromFtoL(state, ss.str(), phaddr, size, concreteValue);
                        }
                    }
                } else if (cache_t1_type_flag_phs[UniquePeripheral(phaddr, pc)] == 2) {
                    value = cache_pt1_type_phs[UniquePeripheral(phaddr, pc)].second & (LSB - 1);
                    getDebugStream() << " TIRQ PT1 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                     << " value = " << hexval(value) << " size =" << hexval(size) << "\n";
                    return klee::ConstantExpr::create(value, size * 8);
                } else {
                    getWarningsStream() << " change mode ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                        << " size =" << hexval(size) << "\n";
                    return switchModefromFtoL(state, ss.str(), phaddr, size, concreteValue);
                }
            } else { // normal mode
                if (cache_t2_type_flag_phs[UniquePeripheral(phaddr, pc)] == T2) {
                    CWMap::iterator itt2 = cache_t2_type_phs[UniquePeripheral(phaddr, pc)].find(sum_hash);
                    if (itt2 != cache_t2_type_phs[UniquePeripheral(phaddr, pc)].end()) {
                        value = cache_t2_type_phs[UniquePeripheral(phaddr, pc)][sum_hash] & (LSB - 1);
                        getDebugStream() << " T2 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                         << "caller pc hash = " << hexval(sum_hash) << " value = " << hexval(value)
                                         << " size =" << hexval(size) << "\n";
                        return klee::ConstantExpr::create(value, size * 8);
                    } else {
                        return switchModefromFtoL(state, ss.str(), phaddr, size, concreteValue);
                    }
                } else {
                    T1PeripheralMap::iterator itt1s = cache_t1_type_flag_phs.find(UniquePeripheral(phaddr, pc));
                    if (itt1s != cache_t1_type_flag_phs.end()) {
                        if (cache_t1_type_flag_phs[UniquePeripheral(phaddr, pc)] == 1) {
                            value = cache_t1_type_phs[UniquePeripheral(phaddr, pc)].second & (LSB - 1);
                        } else if (cache_t1_type_flag_phs[UniquePeripheral(phaddr, pc)] == 2) {
                            value = cache_pt1_type_phs[UniquePeripheral(phaddr, pc)].second & (LSB - 1);
                        } else {
                            getWarningsStream() << "unrecognized cache peripheral type1!\n";
                            exit(-1);
                        }
                        getDebugStream() << " T1 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                         << " value = " << hexval(value) << " size =" << hexval(size) << "\n";
                        return klee::ConstantExpr::create(value, size * 8);
                    } else {
                        return switchModefromFtoL(state, ss.str(), phaddr, size, concreteValue);
                    }
                }
            }
        }
        case T3: {
            if (cache_t3_type_phs[itf->first].size() > 0) {
                value = cache_t3_type_phs[itf->first].front() & (LSB - 1);
                cache_t3_type_phs[itf->first].pop_front();
                if (!fuzzOk) {
                    cache_t3_type_phs[itf->first].push_back(value);
                }
                getDebugStream() << " t3 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                 << " value = " << hexval(value) << " size = " << hexval(size) << "\n";
                return klee::ConstantExpr::create(value, size * 8);
            } else {
                return switchModefromFtoL(state, ss.str(), phaddr, size, concreteValue);
            }
        }
        default: {
            getWarningsStream() << "unrecognized cache peripheral type!\n";
            exit(-1);
        }
    }
}

static bool symbhw_is_mmio_symbolic(struct MemoryDesc *mr, uint64_t physaddr, uint64_t size, void *opaque) {
    PeripheralModelLearning *hw = static_cast<PeripheralModelLearning *>(opaque);
    return hw->isMmioSymbolic(physaddr);
}

static klee::ref<klee::Expr> symbhw_symbread(struct MemoryDesc *mr, uint64_t physaddress,
                                             const klee::ref<klee::Expr> &value, SymbolicHardwareAccessType type,
                                             void *opaque) {
    PeripheralModelLearning *hw = static_cast<PeripheralModelLearning *>(opaque);

    if (DebugSymbHw) {
        hw->getDebugStream(g_s2e_state) << "reading mmio " << hexval(physaddress) << "\n";
    }

    unsigned size = value->getWidth() / 8;
    uint64_t concreteValue = g_s2e_state->toConstantSilent(value)->getZExtValue();
    if (!g_s2e_cache_mode) {
        return hw->onLearningMode(g_s2e_state, SYMB_MMIO, physaddress, size, concreteValue);
        // learningmodetest version
        // return hw->onLearningModeTest(g_s2e_state, SYMB_MMIO, physaddress, size, concreteValue);
    } else {
        return hw->onFuzzingMode(g_s2e_state, SYMB_MMIO, physaddress, size, concreteValue);
    }
}

static void symbhw_symbwrite(struct MemoryDesc *mr, uint64_t physaddress, const klee::ref<klee::Expr> &value,
                             SymbolicHardwareAccessType type, void *opaque) {
    PeripheralModelLearning *hw = static_cast<PeripheralModelLearning *>(opaque);
    uint32_t curPc = g_s2e_state->regs()->getPc();

    if (DebugSymbHw) {
        hw->getDebugStream(g_s2e_state) << "writing mmio " << hexval(physaddress) << " value: " << value
                                        << " pc: " << hexval(curPc) << "\n";
    }
    // test version
    hw->onWritePeripheral(g_s2e_state, physaddress, value);
}

void PeripheralModelLearning::onWritePeripheral(S2EExecutionState *state, uint64_t phaddr,
                                                const klee::ref<klee::Expr> &value) {
    // record all write phs
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);
    plgState->insert_all_rw_phs(phaddr, 1);

    if (isa<klee::ConstantExpr>(value)) {
        uint32_t writeConcreteValue;
        klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(value);
        writeConcreteValue = ce->getZExtValue();
        getDebugStream() << "writing mmio " << hexval(phaddr) << " concrete value: " << hexval(writeConcreteValue)
                         << "\n";
        plgState->update_writeph((uint32_t) phaddr, writeConcreteValue);
    } else {
        uint32_t writeConcreteValue;
        // evaluate symbolic regs
        klee::ref<klee::ConstantExpr> ce;
        ce = dyn_cast<klee::ConstantExpr>(g_s2e_state->concolics->evaluate(value));
        writeConcreteValue = ce->getZExtValue();
        getDebugStream() << "writing mmio " << hexval(phaddr) << " value: " << hexval(writeConcreteValue) << "\n";
        plgState->update_writeph((uint32_t) phaddr, writeConcreteValue);

        TypeFlagPeripheralMap type_flag_phs = plgState->get_type_flag_phs();
        TypeFlagPeripheralMap::iterator itf = type_flag_phs.find(phaddr);
        if (itf != type_flag_phs.end()) {
            if (plgState->get_type_flag_ph_it(phaddr) == T1 && plgState->get_lock_t1_type_flag(phaddr) != 1) {
                if (!state->regs()->getInterruptFlag()) {
                    getDebugStream() << " mmio " << hexval(phaddr) << " change to T0"
                                     << "\n";
                    plgState->insert_type_flag_phs(phaddr, T0);
                } else {
                    if (plgState->get_readphs_count(phaddr) == 1) {
                        getDebugStream() << "IRQ mmio " << hexval(phaddr) << " change to T0"
                                         << "\n";
                        plgState->insert_type_flag_phs(phaddr, T0);
                    } else {
                        for (auto back_sr : possible_irq_srs) { // backup dt1 in interrupt
                            if (back_sr.first.first == phaddr && back_sr.second == state->regs()->getExceptionIndex()) {
                                getDebugStream() << " backup all T0 T1 phaddr " << hexval(phaddr)
                                                 << " pc = " << hexval(back_sr.first.second)
                                                 << " value = " << hexval(writeConcreteValue) << "\n";
                                plgState->insert_pdata_type_phs(back_sr.first, writeConcreteValue);
                            }
                        }
                    }
                }
            }
        }
    }

    /* hw->onSymbolicRegisterWrite.emit(g_s2e_state, SYMB_MMIO, physaddress, writeConcreteValue); */
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

bool PeripheralModelLearning::getPeripheralExecutionState(std::string variablePeripheralName, uint32_t *phaddr,
                                                          uint32_t *pc, uint64_t *ch_value, uint64_t *no) {
    boost::smatch what;
    if (!boost::regex_match(variablePeripheralName, what, PeripheralModelLearningRegEx)) {
        getWarningsStream() << "match false"
                            << "\n";
        exit(0);
        return false;
    }

    if (what.size() != 4) {
        getWarningsStream() << "wrong size = " << what.size() << "\n";
        exit(0);
        return false;
    }

    std::string peripheralAddressStr = what[1];
    std::string pcStr = what[2];
    std::string noStr = what[3];

    std::vector<std::string> v;
    SplitString(peripheralAddressStr, v, "_");
    *phaddr = std::stoull(v[0].c_str(), NULL, 16);
    *pc = std::stoull(v[1].c_str(), NULL, 16);
    *ch_value = std::stoull(pcStr.c_str(), NULL, 16);
    *no = std::stoull(noStr.c_str(), NULL, 10);

    return true;
}

void PeripheralModelLearning::saveKBtoFile(S2EExecutionState *state, uint64_t tb_num) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);

    end = time(NULL);
    durationtime = durationtime + (end - start);
    getWarningsStream(state) << "Learning time = " << durationtime << "s\n";

    T1BNPeripheralMap t1_type_phs = plgState->get_t1_type_phs();
    T1BNPeripheralMap pt1_type_phs = plgState->get_pt1_type_phs();
    T2PeripheralMap t2_type_phs = plgState->get_t2_type_phs();
    TypeFlagPeripheralMap type_flag_phs = plgState->get_type_flag_phs();
    T1PeripheralMap pdata_type_phs = plgState->get_pdata_type_phs();
    T1PeripheralMap pt1_type_flag_all_phs = plgState->get_pt1_type_flag_all_phs();
    TypeFlagPeripheralMap All_rphs;
    TypeFlagPeripheralMap T0_phs;
    TypeFlagPeripheralMap T2_phs;
    TypeFlagPeripheralMap T3_phs;

    round_count++;
    std::size_t index = firmwareName.find_last_of("/\\");
    fileName = s2e()->getOutputDirectory() + "/" + firmwareName.substr(index + 1) +
               "-round" + std::to_string(round_count) + "-state" +
               std::to_string(state->getID()) + "-tbnum" + std::to_string(tb_num) + "_KB.dat";
    std::ofstream fPHKB;
    fPHKB.open(fileName, std::ios::out | std::ios::trunc);

    for (auto itflag : type_flag_phs) {
        if (plgState->get_t0_type_flag_ph_it(itflag.first) == 1) {
            All_rphs[itflag.first] = 1;
            if (itflag.second == T0) {
                T0_phs[itflag.first] = 1;
                fPHKB << "t0_" << hexval(itflag.first) << "_"
                      << "0x0"
                      << "_"
                      << "0x0"
                      << "_"
                      << "0x0" << std::endl;
            }
        }
    }

    for (auto itt1 : t1_type_phs) {
        if (plgState->get_type_flag_ph_it(itt1.first.first) == T1) {
            if (plgState->get_t2_type_flag_ph_it(itt1.first) != T2) {
                All_rphs[itt1.first.first] = 1;
                fPHKB << "t1_" << hexval(itt1.first.first) << "_" << hexval(itt1.first.second) << "_"
                      << hexval(itt1.second.first) << "_" << hexval(itt1.second.second.second) << std::endl;
            }
        }
    }

    for (auto itpt1 : pt1_type_phs) {
        if (plgState->get_type_flag_ph_it(itpt1.first.first) == T1) {
            All_rphs[itpt1.first.first] = 1;
            if (plgState->get_pt1_type_flag_ph_it(itpt1.first) == 2) {
                fPHKB << "pt1_" << hexval(itpt1.first.first) << "_" << hexval(itpt1.first.second) << "_"
                      << hexval(itpt1.second.first) << "_" << hexval(itpt1.second.second.second) << std::endl;
            }
        }
    }

    for (auto itd : pt1_type_flag_all_phs) {
        if (plgState->get_type_flag_ph_it(itd.first.first) == T1) {
            if (plgState->get_pt1_type_flag_ph_it(itd.first) == 1) {
                if (pdata_type_phs.count(itd.first) == 0) {
                    fPHKB << "dt1_" << hexval(itd.first.first) << "_" << hexval(itd.first.second) << "_"
                          << "0x0"
                          << "_"
                          << "0x0" << std::endl;
                } else {
                    fPHKB << "dt1_" << hexval(itd.first.first) << "_" << hexval(itd.first.second) << "_"
                          << "0x0"
                          << "_" << hexval(pdata_type_phs[itd.first]) << std::endl;
                }
            }
        }
    }

    for (auto itt2 : t2_type_phs) {
        All_rphs[itt2.first.first] = 1;
        T2_phs[itt2.first.first] = 1;
        for (auto itt2it : itt2.second) {
            fPHKB << "t2_" << hexval(itt2.first.first) << "_" << hexval(itt2.first.second) << "_"
                  << hexval(itt2it.first) << "_" << hexval(itt2it.second) << std::endl;
        }
    }

    for (auto ituncaches : plgState->get_all_cache_phs()) {
        if (type_flag_phs[ituncaches.first] == T3) {
            std::vector<std::pair<uint64_t, uint32_t>> ituncaches_vec;
            ituncaches_vec.clear();
            for (auto &itun : ituncaches.second) {
                ituncaches_vec.push_back(std::make_pair(itun.first, itun.second));
            }

            std::sort(ituncaches_vec.begin(), ituncaches_vec.end(), CmpByNo());
            All_rphs[ituncaches.first] = 1;
            uint32_t max_t3_size;
            if (plgState->get_readphs_count(ituncaches.first) > plgState->get_t3_size_ph_it(ituncaches.first) &&
                plgState->get_t3_size_ph_it(ituncaches.first) != 0) {
                max_t3_size = plgState->get_t3_size_ph_it(ituncaches.first);
            } else {
                max_t3_size = plgState->get_readphs_count(ituncaches.first);
            }
            getDebugStream() << "t3 size = " << max_t3_size
                             << " read count = " << plgState->get_readphs_count(ituncaches.first) << "\n";
            T3_phs[ituncaches.first] = 1;
            std::vector<uint32_t> unique_T3_values;
            for (auto ituncache_vec : ituncaches_vec) {
                unique_T3_values.push_back(ituncache_vec.second);
                getDebugStream() << "ut3_" << hexval(ituncaches.first) << "_" << hexval(ituncache_vec.second) << "\n";
            }
            std::sort(unique_T3_values.begin(), unique_T3_values.end());
            unique_T3_values.erase(std::unique(unique_T3_values.begin(), unique_T3_values.end()),
                                   unique_T3_values.end());
            if (unique_T3_values.size() < 3) {
                int j = 1;
                for (uint32_t T3_value : unique_T3_values) {
                    if (j <= max_t3_size) {
                        fPHKB << "t3_" << hexval(ituncaches.first) << "_" << hexval(plgState->get_readphs_size(ituncaches.first))
                              << "_" << j++ << "_" << hexval(T3_value) << std::endl;
                    }
                }
            } else {
                int j = 1;
                for (auto ituncache_vec : ituncaches_vec) {
                    if (j <= max_t3_size) {
                        fPHKB << "t3_" << hexval(ituncaches.first) << "_" << hexval(plgState->get_readphs_size(ituncaches.first))
                              << "_" << j++ << "_" << hexval(ituncache_vec.second) << std::endl;
                    }
                }
            }
        }
    }

    writeTIRQPeripheralstoKB(state, fPHKB);

    identifyDataPeripheralRegs(state, fPHKB);

    fPHKB << "\nStatistic:" << std::endl;
    fPHKB << "T0 num = " << T0_phs.size()
          << " T1 num = " << All_rphs.size() - T0_phs.size() - T2_phs.size() - T3_phs.size()
          << " T2 num = " << T2_phs.size() << " T3 num = " << T3_phs.size() << std::endl;
    fPHKB << " All read peripheral regs num = " << All_rphs.size() << std::endl;

    TypeFlagPeripheralMap All_Cond_phs = plgState->get_condition_phs();
    uint32_t CT0 = 0, CT1 = 0, CT2 = 0, CT3 = 0;
    std::vector<uint32_t> cond_phs_vec;
    for (auto ph : plgState->get_all_rw_phs()) {
        cond_phs_vec.push_back(ph.first);
    }

    for (auto c_ph : All_Cond_phs) {
        if (T0_phs[c_ph.first] == 1) {
            CT0++;
            fPHKB << "CT0 " << hexval(c_ph.first) << std::endl;
        } else if (T2_phs[c_ph.first] == 1) {
            CT2++;
            fPHKB << "CT2 " << hexval(c_ph.first) << std::endl;
        } else if (T3_phs[c_ph.first] == 1) {
            CT3++;
            fPHKB << "CT3 " << hexval(c_ph.first) << std::endl;
        } else {
            CT1++;
            fPHKB << "CT1 " << hexval(c_ph.first) << std::endl;
        }
    }

    fPHKB << "CT0 num = " << CT0 << " CT1 num = " << CT1 << " CT2 num = " << CT2 << " CT3 num = " << CT3 << std::endl;
    fPHKB << " All conditional read peripheral regs num = " << All_Cond_phs.size() << std::endl;

    std::sort(cond_phs_vec.begin(), cond_phs_vec.end());
    uint32_t new_ph_start_address = cond_phs_vec[0] & 0xffffff00;
    fPHKB << "Unique peripheral base address = " << hexval(cond_phs_vec[0]) << std::endl;
    for (auto ph : cond_phs_vec) {
        if (ph > new_ph_start_address + 0x100) {
            new_ph_start_address = ph & 0xffffff00;
            fPHKB << "Unique peripheral base address = " << hexval(ph) << std::endl;
        }
    }

    fPHKB << "All_search_path_num = " << all_searched_path_map.size() << " All_path_num = " << all_path_map.size() + 1
          << std::endl;

    fPHKB << "Learning time: " << durationtime << "s" << std::endl;

    fPHKB.close();

    getWarningsStream(state) << "=========KB Extraction Phase Finish===========\n";
}

void PeripheralModelLearning::onARMFunctionCall(S2EExecutionState *state, uint32_t caller_pc, uint64_t function_hash) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);
    if (state->regs()->getInterruptFlag()) {
        if (state->regs()->getExceptionIndex() > 15 && !g_s2e_cache_mode) {
            getDebugStream() << "irq num " << state->regs()->getExceptionIndex() << " caller PC = " << hexval(caller_pc)
                             << "\n";
            updateIRQKB(state, state->regs()->getExceptionIndex(), 1);
        }
        plgState->insert_hashstack(state->regs()->getExceptionIndex(), function_hash);
    } else {
        plgState->insert_hashstack(0, function_hash);
    }
}

void PeripheralModelLearning::onARMFunctionReturn(S2EExecutionState *state, uint32_t return_pc) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);
    if (state->regs()->getInterruptFlag()) {
        plgState->pop_hashstack(state->regs()->getExceptionIndex());
    } else {
        plgState->pop_hashstack(0);
    }
}

void PeripheralModelLearning::onLearningTerminationDetection(S2EExecutionState *state, bool *actual_end,
                                                             uint64_t tb_num) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);

    getDebugStream() << "live state phs save last fork state!! \n";
    getWarningsStream() << "Terminate live state:" << state->getID() << " tb num " << tb_num << "\n";
    if (auto_mode_switch) {
        updateGeneralKB(state, 0, Valid);
        saveKBtoFile(state, tb_num);
        getWarningsStream() << " Mode auto switch from KB phase to dynamic phase!!\n";
        switchModefromLtoF(state);
    } else {
        for (auto itairq : already_used_irq_values) {
            // this feature only used for unit test, so we only enable termination tb num greater than 500
            if (tb_num > 500) {
                break;
            }
            if (plgState->get_type_flag_ph_it(std::get<1>(itairq.first)) != T1 ||
                irq_data_phs[std::get<1>(itairq.first)] == 2) {
                continue;
            }
            if (itairq.second.size() != possible_irq_values[itairq.first].size() && possible_irq_values[itairq.first].size() > 2) {
                getDebugStream() << "ph addr = " << hexval(std::get<1>(itairq.first))
                                 << " pc = " << hexval(std::get<2>(itairq.first))
                                 << " irq no = " << std::get<0>(itairq.first)
                                 << " already trigger number of irq values = " << itairq.second.size()
                                 << " total number of irq values = " << possible_irq_values[itairq.first].size()
                                 << "\n";
                *actual_end = false;
                return;
            }
        }
        updateGeneralKB(state, 0, Valid);
        saveKBtoFile(state, tb_num);
        g_s2e->getCorePlugin()->onEngineShutdown.emit();
        // Flush here just in case ~S2E() is not called (e.g., if atexit()
        // shutdown handler was not called properly).
        g_s2e->flushOutputStreams();
        exit(0);
    }
}

void PeripheralModelLearning::onInvalidStatesDetection(S2EExecutionState *state, uint32_t pc, InvalidStatesType type,
                                                       uint64_t tb_num) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);

    // record every termination points for alive point identification
    plgState->inc_alive_points_count(pc);
    if (plgState->get_alive_points_count(pc) > 5) {
        getWarningsStream() << "====KB extraction phase failed! Please add the alive point: "
                            << hexval(pc) <<" and re-run the learning parse====\n";
        exit(-1);
    }
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

    // remove current state in cache learning mode states
    if (learning_mode_states.size() > 0) {
        auto itles = learning_mode_states.begin();
        for (; itles != learning_mode_states.end();) {
            if (*itles == state) {
                getDebugStream() << "delete current state in learning state " << (*itles)->getID() << "\n";
                learning_mode_states.erase(itles);
            } else {
                itles++;
            }
        }
    }

    // TODO: Do not erase value in T3
    if (!no_new_branch_flag && (!state->regs()->getInterruptFlag())) {
        TypeFlagPeripheralMap type_flag_phs = plgState->get_type_flag_phs();
        for (auto &it : plgState->getlastfork_phs()) {
            for (auto &itch : it.second) {
                if (type_flag_phs[it.first.first] == T3) {
                    getDebugStream() << " t3 loop phs = " << hexval(it.first.first)
                                     << " pc = " << hexval(it.first.second) << " value = " << hexval(itch.second.second)
                                     << " maybe is incorrect\n";
                    // plgState->erase_t3_type_ph_it(it.first.first, itch.second.second);
                    break;
                }
            }
        }
    }

    // remove wrong value in external interrupt value pool
    if (!irq_no_new_branch_flag && state->regs()->getInterruptFlag()) {
        TypeFlagPeripheralMap type_flag_phs = plgState->get_type_flag_phs();
        for (auto &it : plgState->irq_getlastfork_phs(state->regs()->getExceptionIndex())) {
            for (auto &itch : it.second) {
                if (type_flag_phs[it.first.first] == T3) {
                    getDebugStream() << " t3 loop phs = " << hexval(it.first.first)
                                     << " pc = " << hexval(it.first.second) << " value = " << hexval(itch.second.second)
                                     << "\n";
                    break;
                } else if (type_flag_phs[it.first.first] == T1 && state->regs()->getExceptionIndex() > 15) {
                    IRQPhTuple uniqueirqsphs =
                        std::make_tuple(state->regs()->getExceptionIndex(), it.first.first, it.first.second);
                    std::deque<uint32_t>::iterator itirq =
                        std::find(possible_irq_values[uniqueirqsphs].begin(), possible_irq_values[uniqueirqsphs].end(),
                                  itch.second.second);
                    std::deque<uint32_t>::iterator itairq =
                        std::find(already_used_irq_values[uniqueirqsphs].begin(),
                                  already_used_irq_values[uniqueirqsphs].end(), itch.second.second);
                    if (itairq != already_used_irq_values[uniqueirqsphs].end()) {
                        already_used_irq_values[uniqueirqsphs].erase(itairq);
                    }
                    if (itirq != possible_irq_values[uniqueirqsphs].end()) {
                        possible_irq_values[uniqueirqsphs].erase(itirq);
                        impossible_irq_values[uniqueirqsphs].push_back(itch.second.second);
                        getDebugStream() << " remove irq phs = " << hexval(it.first.first)
                                         << " pc = " << hexval(it.first.second)
                                         << " value = " << hexval(itch.second.second) << "\n";
                        break;
                    }
                }
            }
        }
    }

    //// remove current state in cache fork states
    for (int i = 0; i < unsearched_condition_fork_states.size(); i++) {
        auto cfss = unsearched_condition_fork_states[i].begin();
        for (; cfss != unsearched_condition_fork_states[i].end();) {
            if (*cfss == state) {
                getDebugStream() << "delete current state in unused cache t1 state " << (*cfss)->getID() << "\n";
                unsearched_condition_fork_states[i].erase(cfss);
            } else {
                cfss++;
            }
        }
    }

    // remove states in same loop
    if ((!no_new_branch_flag && !state->regs()->getInterruptFlag()) ||
        (!irq_no_new_branch_flag && state->regs()->getInterruptFlag())) {
        if (unsearched_condition_fork_states.back().size() > 1) {
            for (int i = 1; i < unsearched_condition_fork_states.back().size();
                 ++i) { // last it is current state so not add current state
                false_type_phs_fork_states.push_back(unsearched_condition_fork_states.back()[i]);
                getDebugStream() << " remove useless loop fork state in above condition "
                                 << unsearched_condition_fork_states.back()[i]->getID()
                                 << " size = " << unsearched_condition_fork_states.back().size() << "\n";
            }
            std::vector<S2EExecutionState *> unsbfs;
            unsbfs.clear();
            unsbfs.push_back(unsearched_condition_fork_states.back()[0]);
            unsearched_condition_fork_states.pop_back();
            unsearched_condition_fork_states.push_back(unsbfs);
            fs = -1;
        }
    }

    if ((no_new_branch_flag && (!state->regs()->getInterruptFlag())) ||
        (irq_no_new_branch_flag && state->regs()->getInterruptFlag())) {
        unsearched_condition_fork_states.pop_back();
        if (unsearched_condition_fork_states.back().size() > 1) {
            for (int i = 1; i < unsearched_condition_fork_states.back().size();
                 ++i) { // last it is current state so not add current state
                false_type_phs_fork_states.push_back(unsearched_condition_fork_states.back()[i]);
                getDebugStream() << " remove useless loop fork state in above condition "
                                 << unsearched_condition_fork_states.back()[i]->getID()
                                 << " size = " << unsearched_condition_fork_states.back().size() << "\n";
            }
            std::vector<S2EExecutionState *> unsbfs;
            unsbfs.clear();
            unsbfs.push_back(unsearched_condition_fork_states.back()[0]);
            unsearched_condition_fork_states.pop_back();
            unsearched_condition_fork_states.push_back(unsbfs);
            fs = -1;
        }
    }

    // push all useless states together and kill.
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

bool PeripheralModelLearning::ConcreteT3Regs(S2EExecutionState *state) {

    for (unsigned i = 0; i < 13; ++i) {
        unsigned offset = offsetof(CPUARMState, regs[i]);
        target_ulong concreteData;

        klee::ref<klee::Expr> expr = state->regs()->read(offset, sizeof(concreteData) * 8);
        if (!isa<klee::ConstantExpr>(expr)) {
            // evaluate symbolic regs
            klee::ref<klee::ConstantExpr> ce;
            ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(expr));
            concreteData = ce->getZExtValue();
            getDebugStream() << " symbolic reg" << i << " = " << expr << " concrete value = " << hexval(concreteData)
                             << "\n";
            state->regs()->write(offset, &concreteData, sizeof(concreteData));
        }
    }

    return true;
}

void PeripheralModelLearning::onStateForkDecide(S2EExecutionState *state, bool *doFork,
                                                const klee::ref<klee::Expr> &condition, bool *conditionFork) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);
    uint32_t curPc = state->regs()->getPc();

    ArrayVec results;
    findSymbolicObjects(condition, results);
    for (int i = results.size() - 1; i >= 0; --i) { // one cond multiple sym var
        uint32_t phaddr;
        uint32_t pc;
        uint64_t ch_value;
        uint64_t no;
        auto &arr = results[i];

        getPeripheralExecutionState(arr->getName(), &phaddr, &pc, &ch_value, &no);
        if (symbolic_address_count[curPc] > 0) {
            getDebugStream(state) << "can not fork at Symbolic Address: " << hexval(curPc) << "\n";
            plgState->insert_symbolicpc_ph_it(std::make_pair(phaddr, pc));
            getWarningsStream(state) << "Add symbolic phaddr = " << hexval(phaddr) << " pc = " << hexval(pc) << "\n";
            *doFork = false;
            *conditionFork = false;
            continue;
        }

        // let go circle of condition in symbolic pc forking
        if (plgState->get_symbolicpc_ph_it(UniquePeripheral(phaddr, pc)) == 1 && plgState->get_type_flag_ph_it(phaddr) != T1) {
            getWarningsStream(state) << "condition random in symbolic address " << hexval(phaddr)
                                     << " pc = " << hexval(pc) << "\n";
            plgState->inc_symbolicpc_ph_count(UniquePeripheral(phaddr, pc));
            *conditionFork = plgState->get_symbolicpc_ph_count(UniquePeripheral(phaddr, pc)) % 2;
            return;
        }

        if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) {
            getWarningsStream(state) << "condition false in external irq " << hexval(phaddr) << " pc = " << hexval(pc)
                                     << "\n";
            *conditionFork = false;
            return;
        }

        if (plgState->get_type_flag_ph_it(phaddr) == T1) {
            // getWarningsStream() << " T2 type condition phaddr = " << hexval(phaddr) << "\n";
            if (plgState->get_t2_type_flag_ph_it(std::make_pair(phaddr, pc)) == T2) {
                if (plgState->get_pt2_type_flag_ph_it(std::make_pair(phaddr, pc), ch_value) == 1) {
                    *conditionFork = true;
                } else {
                    *conditionFork = false;
                }
            } else {
                if (plgState->get_pt1_type_flag_ph_it(std::make_pair(phaddr, pc)) == 2) {
                    *conditionFork = false;
                    // getWarningsStream() << " condition false t1 phaddr = " << hexval(phaddr) << "\n";
                } else {
                    std::vector<unsigned char> data;
                    *conditionFork = true;
                    ref<Expr> e = state->concolics->evaluate(condition);
                    if (!isa<ConstantExpr>(e)) {
                        getWarningsStream() << "Failed to evaluate concrete value\n";
                        pabort("Failed to evaluate concrete value");
                    }

                    uint32_t condConcreteValue = dyn_cast<ConstantExpr>(e)->getZExtValue();
                    getDebugStream(state) << " condition with phaddr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                          << " current state value = " << hexval(condConcreteValue) << " no = " << no
                                          << "\n";
                }
            }
        } else if (plgState->get_type_flag_ph_it(phaddr) == T3) {
            if (plgState->get_concrete_t3_flag(phaddr) == 1) {
                ConcreteT3Regs(state);
                *conditionFork = false;
                getWarningsStream() << " condition false for already t3 phaddr = " << hexval(phaddr) << "\n";
            } else {
                *conditionFork = true;
                *doFork = true;
            }
        } else if (plgState->get_type_flag_ph_it(phaddr) == T0) {
            *conditionFork = false;
        } else {
            *conditionFork = true;
        }
    }
}

bool comp(std::vector<uint32_t> &v1, std::vector<uint32_t> &v2) {
    for (int i = 0; i < v2.size(); i++) {
        if (std::find(v1.begin(), v1.end(), v2[i]) == v1.end())
            return false;
    }
    return true;
}

void PeripheralModelLearning::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                                     const std::vector<klee::ref<klee::Expr>> &newConditions) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);
    std::map<uint32_t, AllKnowledgeBaseMap> cachefork_phs;
    cachefork_phs.clear();
    bool T3_flag = false;

    std::vector<uint32_t> fork_states_values;
    fork_states_values.clear();

    for (int k = newStates.size() - 1; k >= 0; --k) {
        DECLARE_PLUGINSTATE(PeripheralModelLearningState, newStates[k]);
        ReadPeripheralMap read_size_phs = plgState->get_readphs();
        ArrayVec results;

        findSymbolicObjects(newConditions[0], results);
        for (int i = results.size() - 1; i >= 0; --i) { // one cond multiple sym var
            uint32_t phaddr;
            uint32_t pc;
            uint64_t ch_value;
            uint64_t no;
            auto &arr = results[i];
            std::vector<unsigned char> data;

            getPeripheralExecutionState(arr->getName(), &phaddr, &pc, &ch_value, &no);

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
            uint64_t LSB = ((uint64_t) 1 << (read_size_phs[phaddr].first * 8));
            uint32_t value = condConcreteValue & (LSB - 1);
            fork_states_values.push_back(value);

            // divide irq data regs with sr and cr regs
            if (newStates[k]->regs()->getInterruptFlag()) {
                if (newStates[k]->regs()->getExceptionIndex() > 15) {
                    // used for irq sr type judgement
                    plgState->insert_current_irq_values(phaddr, value);
                }
                irq_data_phs[phaddr] = 1;
            }
            // insert p flag for external irq
            if ((newStates[k]->regs()->getInterruptFlag() && newStates[k]->regs()->getExceptionIndex() > 15) ||
                (plgState->get_irq_flag_ph_it(phaddr) == 1 || plgState->get_irq_flag_ph_it(phaddr) == 2)) {
                getWarningsStream(newStates[k]) << " Note: all possible IRQ value of phaddr = " << hexval(phaddr)
                                                << " pc = " << hexval(pc) << " value = " << hexval(value) << "\n";
                if (possible_irq_srs.find(std::make_pair(phaddr, pc)) != possible_irq_srs.end()) {
                    // save all possible value for t3 phs
                    IRQPhTuple uniqueirqsphs =
                        std::make_tuple(possible_irq_srs[std::make_pair(phaddr, pc)], phaddr, pc);
                    if (plgState->get_type_flag_ph_it(phaddr) == T1) {
                        if (find(possible_irq_values[uniqueirqsphs].begin(), possible_irq_values[uniqueirqsphs].end(),
                                 value) == possible_irq_values[uniqueirqsphs].end() &&
                            ((value & 0xffffffff) != 0xf0f0f0f)) {
                            if (find(impossible_irq_values[uniqueirqsphs].begin(),
                                     impossible_irq_values[uniqueirqsphs].end(),
                                     value) == impossible_irq_values[uniqueirqsphs].end()) {
                                getWarningsStream(newStates[k]) << " Note: New IRQ value of phaddr = " << hexval(phaddr)
                                                                << " pc = " << hexval(pc)
                                                                << " value = " << hexval(value) << "\n";
                                possible_irq_values[uniqueirqsphs].push_back(value);
                            }
                        }
                    }
                } else {
                    getWarningsStream() << "T0 type\n";
                }
            }

            // TODO: No. should be map only in IRQ mode
            if (cachefork_phs[k].count(uniquePeripheral) > 0 &&
                !(newStates[k]->regs()->getInterruptFlag() && newStates[k]->regs()->getExceptionIndex() > 15)) {
                if (cachefork_phs[k][uniquePeripheral].count(ch_value) > 0) {
                    if ((cachefork_phs[k][uniquePeripheral][ch_value].first != no &&
                         cachefork_phs[k][uniquePeripheral][ch_value].second != value &&
                         plgState->get_type_flag_ph_it(phaddr) != T0) ||
                        T3_flag) {
                        T3_flag = true;
                        plgState->insert_type_flag_phs(phaddr, T3);
                        plgState->insert_t3_type_ph_back(phaddr, value);
                        if (plgState->get_t2_type_flag_ph_it(uniquePeripheral) == T2) {
                            plgState->erase_t2_type_phs(uniquePeripheral);
                            getWarningsStream(newStates[k]) << " Note: t2 change to t3 phaddr = " << hexval(phaddr)
                                                            << " size = " << plgState->get_t3_type_ph_size(phaddr)
                                                            << "\n";
                        } else {
                            getWarningsStream(newStates[k]) << " Note: t1 change to t3 phaddr = " << hexval(phaddr)
                                                            << " size = " << plgState->get_t3_type_ph_size(phaddr)
                                                            << "\n";
                        }
                    }
                }
            }

            // update cachefork after T3 check
            cachefork_phs[k][uniquePeripheral][ch_value] = std::make_pair(no, value);
            plgState->insert_cachephs(phaddr, no, value);
            plgState->insert_condition_ph_it(phaddr);
            getWarningsStream(newStates[k]) << " all cache phaddr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                            << " value = " << hexval(value) << " no = " << no
                                            << " width = " << hexval(read_size_phs[phaddr].first) << "\n";

            if (plgState->get_type_flag_ph_it(phaddr) == T3) {
                plgState->insert_t3_type_ph_back(phaddr, value);
                plgState->insert_t3_size_ph_it(phaddr, plgState->get_readphs_count(phaddr));
                if (plgState->get_concrete_t3_flag(phaddr) == 1 && state == newStates[k]) {
                    ConcreteT3Regs(newStates[k]);
                } else if ((plgState->get_t3_type_ph_size(phaddr) > 5 ||
                            plgState->get_readphs_count(phaddr) >= t3_max_symbolic_count) &&
                           state == newStates[k]) {
                    std::vector<std::pair<uint64_t, uint32_t>> ituncaches;
                    ituncaches.clear();
                    for (auto &itun : plgState->get_cache_phs(phaddr)) {
                        ituncaches.push_back(std::make_pair(itun.first, itun.second));
                    }
                    std::sort(ituncaches.begin(), ituncaches.end(), CmpByNo());
                    plgState->clear_t3_type_phs(phaddr);
                    for (auto ituncache : ituncaches) {
                        plgState->push_t3_type_ph_back(phaddr, ituncache.second);
                    }
                    getWarningsStream(newStates[k]) << " Note: concrete t3 phaddr = " << hexval(phaddr) << "\n";
                    plgState->insert_concrete_t3_flag(phaddr, 1);
                    ConcreteT3Regs(newStates[k]);
                }
            } else {
                if (newStates[k]->regs()->getInterruptFlag() == 0) {
                    getDebugStream(newStates[k]) << " backup all T0 T1 phaddr " << hexval(phaddr)
                                                 << " value = " << hexval(value) << "\n";
                    plgState->insert_pdata_type_phs(uniquePeripheral, value);
                    if (plgState->get_type_flag_ph_it(phaddr) == T1 && value != 0 && newStates[k] == state) {
                        plgState->insert_lock_t1_type_flag(phaddr, 1);
                        getDebugStream() << "Note: lock t1 " << hexval(phaddr) << "\n";
                    }
                }
            }

            // update path map
            if (newStates[k] == state) {
                all_searched_path_map[newStates[k]->getID()] = 1;
            } else {
                all_path_map[newStates[k]->getID()] = 1;
            }

        } // each condition

        // push fork states in interrupt
        if (newStates[k]->regs()->getInterruptFlag()) {
            if (newStates[k] != state) {
                getDebugStream() << "push irq state" << newStates[k]->getID() << "\n";
                irq_states.push_back(newStates[k]);
            }
        }
        // push states to learning mode for auto state transfer
        if (find(learning_mode_states.begin(), learning_mode_states.end(), newStates[k]) ==
            learning_mode_states.end()) {
            learning_mode_states.push_back(newStates[k]);
        }

    } // each new State

    uint32_t current_pc = state->regs()->getPc();
    std::pair<uint32_t, std::vector<uint32_t>> last_fork_cond = plgState->get_last_fork_cond();
    plgState->insert_last_fork_cond(current_pc, fork_states_values);
    if (last_fork_cond.first == current_pc && comp(last_fork_cond.second, fork_states_values) &&
        comp(fork_states_values, last_fork_cond.second)) {
        for (int k = newStates.size() - 1; k >= 0; --k) {
            DECLARE_PLUGINSTATE(PeripheralModelLearningState, newStates[k]);
            // only update kb for new condition
            if (newStates[k]->regs()->getInterruptFlag()) {
                plgState->irq_clearlastfork_phs(newStates[k]->regs()->getExceptionIndex());
                for (auto &it : cachefork_phs[k]) {
                    for (auto &itch : it.second) {
                        plgState->irq_insertlastfork_phs(newStates[k]->regs()->getExceptionIndex(), it.first,
                                                         itch.first, itch.second);
                    }
                }
            } else {
                plgState->clearlastfork_phs();
                for (auto &it : cachefork_phs[k]) {
                    for (auto &itch : it.second) {
                        plgState->insertlastfork_phs(it.first, itch.first, itch.second);
                    }
                }
            }
            // push back new loop state
            if (newStates[k] != state) {
                unsearched_condition_fork_states.back().push_back(newStates[k]);
            }
        }
        getWarningsStream(state) << "fork cond in the loop !!" << hexval(current_pc) << "\n";
        return;
    } else {
        // set fork flag
        if (state->regs()->getInterruptFlag()) {
            irq_no_new_branch_flag = false;
        } else {
            no_new_branch_flag = false;
        }

        for (int k = newStates.size() - 1; k >= 0; --k) {
            // push back new states
            if (newStates[k] != state) {
                std::vector<S2EExecutionState *> condition_fork_states; // forking states in each condition
                condition_fork_states.clear();
                condition_fork_states.push_back(newStates[k]);
                unsearched_condition_fork_states.push_back(condition_fork_states);
            }
        }
    }

    // update KB
    for (int k = newStates.size() - 1; k >= 0; --k) {
        DECLARE_PLUGINSTATE(PeripheralModelLearningState, newStates[k]);
        // cache the possiable status phs in corresponding state and insert lask fork state for further choices
        // interrupt mode
        if (newStates[k]->regs()->getInterruptFlag()) {
            if (newStates[k]->regs()->getExceptionIndex() > 15) {
                getDebugStream() << " donot store irq phs \n";
            } else {
                if (newStates[k] == state) {
                    updateGeneralKB(newStates[k], newStates[k]->regs()->getExceptionIndex(), Valid);
                }
            }
            plgState->irq_clearlastfork_phs(newStates[k]->regs()->getExceptionIndex());
            for (auto &it : cachefork_phs[k]) {
                for (auto &itch : it.second) {
                    plgState->irq_insertlastfork_phs(newStates[k]->regs()->getExceptionIndex(), it.first, itch.first,
                                                     itch.second);
                }
            }
        } else { // normal mode
            if (newStates[k] == state) {
                updateGeneralKB(newStates[k], 0, Valid);
            } // current state
            plgState->clearlastfork_phs();
            for (auto &it : cachefork_phs[k]) {
                for (auto &itch : it.second) {
                    plgState->insertlastfork_phs(it.first, itch.first, itch.second);
                }
            }
        }
    }
}

void PeripheralModelLearning::onStateKill(S2EExecutionState *state) {

    if (!g_s2e_cache_mode) {
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

        if (learning_mode_states.size() > 0) {
            auto itles = learning_mode_states.begin();
            for (; itles != learning_mode_states.end();) {
                if (*itles == state) {
                    learning_mode_states.erase(itles);
                } else {
                    itles++;
                }
            }
        }

        for (int i = 0; i < unsearched_condition_fork_states.size(); i++) {
            auto cfss = unsearched_condition_fork_states[i].begin();
            for (; cfss != unsearched_condition_fork_states[i].end();) {
                if (*cfss == state) {
                    getDebugStream() << i << " delete cache condition state " << state->getID() << "\n";
                    unsearched_condition_fork_states[i].erase(cfss);
                    if (unsearched_condition_fork_states[i].size() == 0) {
                        getWarningsStream() << "the empty condition unique fork state is " << i
                                            << " total condtions is " << unsearched_condition_fork_states.size()
                                            << "\n";
                        ForkStateStack::iterator cdss = unsearched_condition_fork_states.begin() + i;
                        unsearched_condition_fork_states.erase(cdss);
                        i--;
                        break;
                    }
                } else {
                    cfss++;
                }
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

void PeripheralModelLearning::updateIRQKB(S2EExecutionState *state, uint32_t irq_no, uint32_t crflag) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);
    std::deque<UniquePeripheral> current_irq_phs = plgState->get_current_irq_values();
    PeripheralMap irq_cr_phs;
    PeripheralMap irq_sr_phs;

    uint32_t last_cr_phaddr = 0;
    for (auto &current_irq_ph : current_irq_phs) {
        if (plgState->get_type_flag_ph_it(current_irq_ph.first) == T1) {
            irq_sr_phs[current_irq_ph.first] = current_irq_ph.second;
        } else if (plgState->get_type_flag_ph_it(current_irq_ph.first) == T0) {
            irq_cr_phs[current_irq_ph.first] = current_irq_ph.second;
            last_cr_phaddr = current_irq_ph.first;
        }
    }

    getWarningsStream() << " irq cr count = " << hexval(irq_crs.count(irq_no))
                        << " cr phs size = " << hexval(irq_cr_phs.size())
                        << " sr phs size = " << hexval(irq_sr_phs.size())
                        << " irq regs count = " << hexval(current_irq_phs.size()) << "\n";
    // in case no cr value in condtion
    if (!crflag) {
        if (irq_crs.count(irq_no) > 0 && irq_cr_phs.size() == 0 && irq_sr_phs.size() > 0) {
            uint32_t sr_phaddr;
            uint32_t value;
            for (auto &irq_sr_ph : irq_sr_phs) {
                sr_phaddr = irq_sr_ph.first;
                value = irq_sr_ph.second;
                getDebugStream() << " control sr type irq phs = " << hexval(sr_phaddr) << "\n";
                if (plgState->get_irq_flag_ph_it(sr_phaddr) == 2) {
                    uint32_t cr_phaddr;
                    for (auto itcr : irq_crs[irq_no]) {
                        cr_phaddr = itcr.first;
                        break;
                    }
                    plgState->insert_tirqc_type_phs(irq_no, sr_phaddr, cr_phaddr, plgState->get_writeph(cr_phaddr),
                                                    value);
                    getWarningsStream() << " Add Empty TIRQC type ph addr = " << hexval(sr_phaddr)
                                        << " value = " << hexval(value) << " cr phaddr = " << hexval(cr_phaddr)
                                        << " cr value =" << hexval(plgState->get_writeph(cr_phaddr)) << "\n";
                } else if (enable_fuzzing) {
                    // TODO: how add fuzzing mode judegment
                    plgState->insert_irq_flag_phs(irq_sr_ph.first, 1);
                }
            }
        } else if (irq_crs.count(irq_no) > 0 && irq_cr_phs.size() == 1 && irq_sr_phs.size() == 1) {
            for (auto &irq_sr_ph : irq_sr_phs) {
                if (plgState->get_irq_flag_ph_it(irq_sr_ph.first) != 2) {
                    getWarningsStream() << " CR irq phs2 " << hexval(irq_sr_ph.first) << "\n";
                    // plgState->insert_irq_flag_phs(irq_sr_ph.first, 1);
                }
            }
        }
    }

    if (crflag) {
        if (irq_sr_phs.size() > 0 && irq_cr_phs.size() > 0) {
            for (auto &irq_sr_ph : irq_sr_phs) {
                // TODO: deal with previous values
                plgState->insert_irq_flag_phs(irq_sr_ph.first, 2);
                plgState->insert_tirqc_type_phs(irq_no, irq_sr_ph.first, last_cr_phaddr, irq_cr_phs[last_cr_phaddr],
                                                irq_sr_ph.second);
                getWarningsStream() << " Add TIRQC type ph addr = " << hexval(irq_sr_ph.first)
                                    << " value = " << hexval(irq_sr_ph.second)
                                    << " cr phaddr = " << hexval(last_cr_phaddr)
                                    << " cr value =" << hexval(irq_cr_phs[last_cr_phaddr]) << "\n";
            }
        } else {
            getWarningsStream() << " CR size = " << irq_cr_phs.size() << "\n";
            for (auto &irq_sr_ph : irq_sr_phs) {
                if (plgState->get_irq_flag_ph_it(irq_sr_ph.first) != 2) {
                    plgState->insert_irq_flag_phs(irq_sr_ph.first, 1);
                    getDebugStream() << " CR irq phs1 " << hexval(irq_sr_ph.first) << "\n";
                } else if (irq_crs.count(irq_no) == 1) {
                    uint32_t cr_phaddr;
                    for (auto itcr : irq_crs[irq_no]) {
                        cr_phaddr = itcr.first;
                        break;
                    }
                    // IRQPhTuple uniqueirqsphs = std::make_tuple(irq_no, irq_sr_ph.first, irq_sr_ph.second);
                    getWarningsStream() << " Add possible TIRQC type ph addr = " << hexval(irq_sr_ph.first)
                                        << " cr phaddr = " << hexval(cr_phaddr)
                                        << " cr value =" << hexval(plgState->get_writeph(cr_phaddr)) << "\n";
                    for (auto &irq_sr_ph : irq_sr_phs) {
                        plgState->insert_tirqc_type_phs(irq_no, irq_sr_ph.first, cr_phaddr,
                                                        plgState->get_writeph(cr_phaddr), irq_sr_ph.second);
                    }
                }
            }
        }
        plgState->clear_current_irq_values();
    }
}

void PeripheralModelLearning::updateGeneralKB(S2EExecutionState *state, uint32_t irq_num, uint32_t reason_flag) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);

    AllKnowledgeBaseMap last_fork_phs;
    if (irq_num > 15) {
        getWarningsStream() << "do store phs in external irqs\n";
    } else if (irq_num == 0) {
        last_fork_phs = plgState->getlastfork_phs();
    } else {
        last_fork_phs = plgState->irq_getlastfork_phs(state->regs()->getExceptionIndex());
    }

    if (reason_flag == Valid) {
        TypeFlagPeripheralMap type_flag_phs = plgState->get_type_flag_phs();
        for (auto &it : last_fork_phs) {
            for (auto &itch : it.second) {
                if (type_flag_phs[it.first.first] == T0) {
                    if (itch.second.second == plgState->get_writeph(it.first.first)) {
                        getDebugStream() << " t0 phs = " << hexval(it.first.first) << " write = " << hexval(itch.first)
                                         << " value = " << hexval(itch.second.second) << "\n";
                        // plgState->insert_t0_type_flag_phs(it.first.first, 1);
                        break;
                    }
                } else if (type_flag_phs[it.first.first] == T1) {
                    if (plgState->get_t2_type_flag_ph_it(it.first) != T2) {
                        T1BNPeripheralMap t1_type_phs = plgState->get_t1_type_phs();
                        T1BNPeripheralMap::iterator itt1 = t1_type_phs.find(it.first);
                        if (itt1 != t1_type_phs.end()) { // deal with t1
                            if (itt1->second.second.second != itch.second.second) {
                                if (itt1->second.first == itch.first) {
                                    plgState->insert_type_flag_phs(it.first.first, T3);
                                    getDebugStream(state)
                                        << " Note: t1 change to t3 phaddr = " << hexval(it.first.first)
                                        << " pc = " << hexval(it.first.second)
                                        << " value = " << hexval(itt1->second.second.second) << "\n";
                                    getDebugStream(state)
                                        << " Note: t1 change to t3 phaddr = " << hexval(it.first.first)
                                        << " pc = " << hexval(it.first.second)
                                        << " value = " << hexval(itch.second.second) << "\n";
                                    plgState->insert_t3_type_ph_back(it.first.first, itt1->second.second.second);
                                    plgState->insert_t3_type_ph_back(it.first.first, itch.second.second);
                                    break;
                                } else {
                                    plgState->insert_t2_type_phs(it.first, itt1->second.first,
                                                                 itt1->second.second.second);
                                    plgState->insert_t2_type_phs(it.first, itch.first, itch.second.second);
                                    plgState->insert_t2_type_flag_phs(it.first, T2);
                                    getDebugStream() << " Note: t1 change to t2 phaddr = " << hexval(it.first.first)
                                                     << " pc = " << hexval(it.first.second)
                                                     << " hash = " << hexval(itt1->second.first)
                                                     << " value = " << hexval(itt1->second.second.second) << "\n";
                                    getDebugStream() << " Note: t1 change to t2 phaddr = " << hexval(it.first.first)
                                                     << " pc = " << hexval(it.first.second)
                                                     << " hash = " << hexval(itch.first)
                                                     << " value = " << hexval(itch.second.second) << "\n";
                                    continue;
                                }
                            }
                        } else { // deal with possible t1
                            T1BNPeripheralMap pt1_type_phs = plgState->get_pt1_type_phs();
                            T1BNPeripheralMap::iterator itpt1 = pt1_type_phs.find(it.first);
                            if (itpt1 != pt1_type_phs.end()) {
                                if (itpt1->second.second.second != itch.second.second) {
                                    if (plgState->get_pt1_type_flag_ph_it(it.first) != 1 ||
                                        itpt1->second.first != itch.first) {
                                        if (itpt1->second.first == itch.first) {
                                            plgState->insert_type_flag_phs(it.first.first, T3);
                                            getDebugStream(state)
                                                << " Note: pt1 change to t3 phaddr = " << hexval(it.first.first)
                                                << " pc = " << hexval(it.first.second)
                                                << " value = " << hexval(itpt1->second.second.second) << "\n";
                                            getDebugStream(state)
                                                << " Note: pt1 change to t3 phaddr = " << hexval(it.first.first)
                                                << " pc = " << hexval(it.first.second)
                                                << " value = " << hexval(itch.second.second) << "\n";
                                            plgState->insert_t3_type_ph_back(it.first.first,
                                                                             itpt1->second.second.second);
                                            plgState->insert_t3_type_ph_back(it.first.first, itch.second.second);
                                            break;
                                        } else {
                                            plgState->insert_t2_type_phs(it.first, itpt1->second.first,
                                                                         itpt1->second.second.second);
                                            plgState->insert_t2_type_phs(it.first, itch.first, itch.second.second);
                                            getDebugStream()
                                                << " Note: pt1 change to t2 phaddr = " << hexval(it.first.first)
                                                << " pc = " << hexval(it.first.second)
                                                << " hash = " << hexval(itpt1->second.first)
                                                << " value = " << hexval(itpt1->second.second.second) << "\n";
                                            getDebugStream()
                                                << " Note: pt1 change to t2 phaddr = " << hexval(it.first.first)
                                                << " pc = " << hexval(it.first.second)
                                                << " hash = " << hexval(itch.first)
                                                << " value = " << hexval(itch.second.second) << "\n";
                                            plgState->insert_t2_type_flag_phs(it.first, T2);
                                            continue;
                                        }
                                    } else {
                                        plgState->insert_pt1_type_phs(it.first, itch.first, itch.second);
                                        getDebugStream() << "  Update possible1 t1 phs = " << hexval(it.first.first)
                                                         << " pc = " << hexval(it.first.second)
                                                         << " hash = " << hexval(itch.first)
                                                         << " value = " << hexval(itch.second.second) << "\n";
                                    }
                                }
                            } else {
                                plgState->insert_pt1_type_phs(it.first, itch.first, itch.second);
                                getDebugStream() << "  Add pt1 phs = " << hexval(it.first.first)
                                                 << " pc = " << hexval(it.first.second)
                                                 << " hash = " << hexval(itch.first)
                                                 << " value = " << hexval(itch.second.second) << "\n";
                            }
                        }
                    } else {
                        CWMap itt2s = plgState->get_t2_type_samepc_phs(it.first);
                        CWMap::iterator itt2 = itt2s.find(itch.first);
                        if (itt2 != itt2s.end()) {
                            if (itch.second.second != itt2->second) {
                                plgState->erase_t2_type_phs(it.first);
                                plgState->insert_type_flag_phs(it.first.first, T3);
                                plgState->insert_t3_type_ph_back(it.first.first, itt2->second);
                                plgState->insert_t3_type_ph_back(it.first.first, itch.second.second);
                                getDebugStream(state) << " Note: t2 change to t3 phaddr = " << hexval(it.first.first)
                                                      << " pc = " << hexval(it.first.second)
                                                      << " value = " << hexval(itt2->second) << "\n";
                                getDebugStream(state) << " Note: t2 change to t3 phaddr = " << hexval(it.first.first)
                                                      << " pc = " << hexval(it.first.second)
                                                      << " value = " << hexval(itch.second.second) << "\n";
                                break;
                            } else if (plgState->get_cache_phs(it.first.first).size() > 100) {
                                getDebugStream() << " already many times t2 phs = " << hexval(it.first.first)
                                                 << " pc = " << hexval(it.first.second)
                                                 << " hash = " << hexval(itch.first)
                                                 << " value = " << hexval(itch.second.second) << "\n";
                            } else {
                                getDebugStream() << " already t2 phs = " << hexval(it.first.first)
                                                 << " pc = " << hexval(it.first.second)
                                                 << " hash = " << hexval(itch.first)
                                                 << " value = " << hexval(itch.second.second) << "\n";
                            }
                        } else {
                            if (itt2s.size() > t2_max_context) {
                                std::deque<uint32_t> loop_type_ph_vector;
                                for (auto itt2e : itt2s) {
                                    loop_type_ph_vector.push_back(itt2e.second);
                                }
                                std::sort(loop_type_ph_vector.begin(), loop_type_ph_vector.end());
                                loop_type_ph_vector.erase(
                                    std::unique(loop_type_ph_vector.begin(), loop_type_ph_vector.end()),
                                    loop_type_ph_vector.end());
                                for (auto itt2v : loop_type_ph_vector) {
                                    plgState->insert_t3_type_ph_back(it.first.first, itt2v);
                                    getDebugStream(state)
                                        << " Note: t2 oversize we will change t2 change to t3 phaddr = "
                                        << hexval(it.first.first) << " pc = " << hexval(it.first.second)
                                        << " value = " << hexval(itt2v) << "\n";
                                }
                                plgState->erase_t2_type_phs(it.first);
                                plgState->insert_t3_type_ph_back(it.first.first, itch.second.second);
                                plgState->insert_type_flag_phs(it.first.first, T3);
                                break;
                            } else {
                                plgState->insert_t2_type_phs(it.first, itch.first, itch.second.second);
                                getDebugStream()
                                    << "Add pt2 phs = " << hexval(it.first.first) << " pc = " << hexval(it.first.second)
                                    << " hash = " << hexval(itch.first) << " value = " << hexval(itch.second.second)
                                    << "\n";
                            }
                        }
                    }
                } else if (type_flag_phs[it.first.first] == T3) {
                    plgState->insert_cachephs(it.first.first, itch.second.first, itch.second.second);
                    getDebugStream() << " Add t3 loop phs = " << hexval(it.first.first)
                                     << " no = " << hexval(itch.second.first)
                                     << " value = " << hexval(itch.second.second) << "\n";
                    plgState->insert_t3_type_ph_back(it.first.first, itch.second.second);
                    break;
                } else {
                    getWarningsStream() << "Unknown Type!!!!\n";
                }
            }
        }
    }

    if (reason_flag == Invlid) {
        TypeFlagPeripheralMap type_flag_phs = plgState->get_type_flag_phs();
        for (auto &it : last_fork_phs) {
            for (auto &itch : it.second) {
                if (type_flag_phs[it.first.first] == T0) {
                    getWarningsStream() << "Return back to T1 ph = " << hexval(it.first.first) << "\n";
                    plgState->insert_type_flag_phs(it.first.first, T1);
                    plgState->insert_lock_t1_type_flag(it.first.first, 1);
                    plgState->insert_t1_type_phs(it.first, itch.first, itch.second);
                    getDebugStream() << "  Add t1 phs = " << hexval(it.first.first)
                                     << " pc = " << hexval(it.first.second) << " hash = " << hexval(itch.first)
                                     << " value = " << hexval(itch.second.second) << "\n";
                    for (auto t0_ph : plgState->get_t0_type_phs(it.first.first)) { // move all previous t0 to t1
                        if (t0_ph.first != it.first.second) {
                            plgState->insert_pt1_type_phs(std::make_pair(it.first.first, t0_ph.first),
                                                          t0_ph.second.first, t0_ph.second.second);
                            getDebugStream() << "  Add pt1 phs = " << hexval(it.first.first)
                                             << " pc = " << hexval(t0_ph.first)
                                             << " hash = " << hexval(t0_ph.second.first)
                                             << " value = " << hexval(t0_ph.second.second.second) << "\n";
                        }
                    }
                } else if (type_flag_phs[it.first.first] == T1) {
                    if (plgState->get_t2_type_flag_ph_it(it.first) == T2) {
                        CWMap itt2s = plgState->get_t2_type_samepc_phs(it.first);
                        CWMap::iterator itt2 = itt2s.find(itch.first);
                        if (itt2 != itt2s.end() && plgState->get_pt2_type_flag_ph_it(it.first, itch.first) == 3) {
                            if (itch.second.second != itt2->second) {
                                plgState->erase_t2_type_phs(it.first);
                                plgState->insert_type_flag_phs(it.first.first, T3);
                                plgState->insert_t3_type_ph_back(it.first.first, itt2->second);
                                plgState->insert_t3_type_ph_back(it.first.first, itch.second.second);
                                getDebugStream(state) << " Note: t2 change to t3 phaddr = " << hexval(it.first.first)
                                                      << " pc = " << hexval(it.first.second)
                                                      << " hash = " << hexval(itch.first)
                                                      << " value = " << hexval(itt2->second) << "\n";
                                getDebugStream(state) << " Note: t2 change to t3 phaddr = " << hexval(it.first.first)
                                                      << " pc = " << hexval(it.first.second)
                                                      << " value = " << hexval(itch.second.second) << "\n";
                                break;
                            } else if (plgState->get_cache_phs(it.first.first).size() > 100) {
                                getDebugStream() << " already many times t2 phs = " << hexval(it.first.first)
                                                 << " pc = " << hexval(it.first.second)
                                                 << " hash = " << hexval(itch.first)
                                                 << " value = " << hexval(itch.second.second) << "\n";
                            } else {
                                getDebugStream() << " already t2 phs = " << hexval(it.first.first)
                                                 << " pc = " << hexval(it.first.second)
                                                 << " hash = " << hexval(itch.first)
                                                 << " value = " << hexval(itch.second.second) << "\n";
                            }
                        } else {
                            if (itt2s.size() > t2_max_context) {
                                std::deque<uint32_t> loop_type_ph_vector;
                                for (auto itt2e : itt2s) {
                                    loop_type_ph_vector.push_back(itt2e.second);
                                }
                                std::sort(loop_type_ph_vector.begin(), loop_type_ph_vector.end());
                                loop_type_ph_vector.erase(
                                    std::unique(loop_type_ph_vector.begin(), loop_type_ph_vector.end()),
                                    loop_type_ph_vector.end());
                                for (auto itt2v : loop_type_ph_vector) {
                                    plgState->insert_t3_type_ph_back(it.first.first, itt2v);
                                    getDebugStream(state)
                                        << " Note: t2 oversize we will change t2 change to t3 phaddr = "
                                        << hexval(it.first.first) << " pc = " << hexval(it.first.second)
                                        << " value = " << hexval(itt2v) << "\n";
                                }
                                plgState->insert_type_flag_phs(it.first.first, T3);
                                plgState->erase_t2_type_phs(it.first);
                                plgState->insert_t3_type_ph_back(it.first.first, itch.second.second);
                                break;
                            } else {
                                plgState->insert_t2_type_phs(it.first, itch.first, itch.second.second);
                                plgState->insert_pt2_type_flag_ph_it(it.first, itch.first, 3);
                                getDebugStream() << "Add lock t2 phs = " << hexval(it.first.first)
                                                 << " pc = " << hexval(it.first.second)
                                                 << " hash = " << hexval(itch.first)
                                                 << " value = " << hexval(itch.second.second) << "\n";
                            }
                        }
                    } else {
                        T1BNPeripheralMap t1_type_phs = plgState->get_t1_type_phs();
                        T1BNPeripheralMap::iterator itt1 = t1_type_phs.find(it.first);
                        if (itt1 != t1_type_phs.end()) { // deal with t1
                            if (itt1->second.second.second != itch.second.second &&
                                itt1->second.second.first != itch.second.first) { // different value and no
                                if (itt1->second.first == itch.first) {           // same hash
                                    plgState->insert_type_flag_phs(it.first.first, T3);
                                    getDebugStream(state)
                                        << " Note: t1 change to t3 phaddr = " << hexval(it.first.first)
                                        << " pc = " << hexval(it.first.second)
                                        << " value = " << hexval(itt1->second.second.second) << "\n";
                                    getDebugStream(state)
                                        << " Note: t1 change to t3 phaddr = " << hexval(it.first.first)
                                        << " pc = " << hexval(it.first.second)
                                        << " value = " << hexval(itch.second.second) << "\n";
                                    plgState->insert_t3_type_ph_back(it.first.first, itt1->second.second.second);
                                    plgState->insert_t3_type_ph_back(it.first.first, itch.second.second);
                                    break;
                                } else {
                                    plgState->insert_t2_type_phs(it.first, itt1->second.first,
                                                                 itt1->second.second.second);
                                    plgState->insert_t2_type_phs(it.first, itch.first, itch.second.second);
                                    plgState->insert_t2_type_flag_phs(it.first, T2);
                                    getDebugStream() << " Note: t1 change to t2 phaddr = " << hexval(it.first.first)
                                                     << " pc = " << hexval(it.first.second)
                                                     << " hash = " << hexval(itt1->second.first)
                                                     << " value = " << hexval(itt1->second.second.second) << "\n";
                                    getDebugStream() << " Note: t1 change to t2 phaddr = " << hexval(it.first.first)
                                                     << " pc = " << hexval(it.first.second)
                                                     << " hash = " << hexval(itch.first)
                                                     << " value = " << hexval(itch.second.second) << "\n";
                                    continue;
                                }
                            } else {
                                plgState->insert_t1_type_phs(it.first, itch.first, itch.second);
                                getDebugStream() << "  Update t1 phs = " << hexval(it.first.first)
                                                 << " pc = " << hexval(it.first.second)
                                                 << " hash = " << hexval(itch.first)
                                                 << " value = " << hexval(itch.second.second) << "\n";
                            }
                        } else {
                            T1BNPeripheralMap pt1_type_phs = plgState->get_pt1_type_phs();
                            T1BNPeripheralMap::iterator itpt1 = pt1_type_phs.find(it.first);
                            if (itpt1 != pt1_type_phs.end()) {
                                plgState->erase_pt1_type_ph_it(it.first);
                            }
                            plgState->insert_lock_t1_type_flag(it.first.first, 1);
                            plgState->insert_t1_type_phs(it.first, itch.first, itch.second);
                            getDebugStream() << "  Add t1 phs = " << hexval(it.first.first)
                                             << " pc = " << hexval(it.first.second) << " hash = " << hexval(itch.first)
                                             << " value = " << hexval(itch.second.second) << "\n";
                        }
                    }
                } else if (type_flag_phs[it.first.first] == T3) {
                    plgState->insert_cachephs(it.first.first, itch.second.first, itch.second.second);
                    getDebugStream() << " Add t3 loop phs = " << hexval(it.first.first)
                                     << " no = " << hexval(itch.second.first)
                                     << " value = " << hexval(itch.second.second) << "\n";
                    plgState->insert_t3_type_ph_back(it.first.first, itch.second.second);
                    break;
                } else {
                    getWarningsStream() << "Unknown Type!!!!\n";
                }
            }
        }
    }
}

void PeripheralModelLearning::onExceptionExit(S2EExecutionState *state, uint32_t irq_no) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);

    getWarningsStream() << "Interrupt exit irq num = " << hexval(irq_no) << "\n";
    // external irqs
    if (irq_no > 15) {
        if (irq_crs.count(irq_no) == 0) {
            for (auto irq_sr : irq_srs[irq_no]) {
                if (plgState->get_irq_flag_ph_it(irq_sr) != 2 && irq_data_phs[irq_sr] != 2) {
                    getWarningsStream() << " status irq phs type 1 " << hexval(irq_sr) << "\n";
                    plgState->insert_irq_flag_phs(irq_sr, 1);
                }
            }
        } else if (irq_crs[irq_no].size() == 1) {
            updateIRQKB(state, irq_no, 0);
        }
        plgState->clear_current_irq_values();
    } else {
        // deal with unstored possible control and status phs when end interrupt
        updateGeneralKB(state, irq_no, Valid);
    }
    irq_no_new_branch_flag = true;
}

void PeripheralModelLearning::onStateSwitch(S2EExecutionState *currentState, S2EExecutionState *nextState) {

    getDebugStream() << "next irq flag = " << nextState->regs()->getInterruptFlag()
                     << " previous irq flag = " << currentState->regs()->getInterruptFlag() << "\n";

    // phs model learning
    getDebugStream() << nextState->regs()->getInterruptFlag()
                     << " flag irq_no_new_branch_flag = " << irq_no_new_branch_flag
                     << nextState->regs()->getInterruptFlag() << " flag no_new_branch_flag = " << no_new_branch_flag
                     << "\n";
    if (!nextState->regs()->getInterruptFlag() && !currentState->regs()->getInterruptFlag()) {
        updateGeneralKB(nextState, 0, Invlid);
        // update flag
        no_new_branch_flag = true;
    }

    // irq mode
    if (nextState->regs()->getInterruptFlag() && currentState->regs()->getInterruptFlag()) {
        updateGeneralKB(nextState, nextState->regs()->getExceptionIndex(), Invlid);
        // update flag
        irq_no_new_branch_flag = true;
    }
}

void PeripheralModelLearning::onSymbolicAddress(S2EExecutionState *state, ref<Expr> virtualAddress,
                                                uint64_t concreteAddress, bool &concretize,
                                                CorePlugin::symbolicAddressReason reason) {
    uint32_t curPc;
    curPc = state->regs()->getPc();
    symbolic_address_count[curPc]++;
}

klee::ref<klee::Expr> PeripheralModelLearning::switchModefromFtoL(S2EExecutionState *state, std::string ss,
                                                                  uint32_t phaddr, unsigned size,
                                                                  uint64_t concreteValue) {
    DECLARE_PLUGINSTATE(PeripheralModelLearningState, state);
    uint32_t pc = state->regs()->getPc();
    getWarningsStream() << "New peripheral has found, ph addr = " << hexval(phaddr) << " pc = " << hexval(pc) << "\n";

    uint64_t sum_hash;
    if (state->regs()->getInterruptFlag()) {
        sum_hash = plgState->get_current_hash(state->regs()->getExceptionIndex());
    } else {
        sum_hash = plgState->get_current_hash(0);
    }

    std::stringstream sum_hashStream;
    sum_hashStream << hexval(sum_hash);
    ss = ss + "_" + sum_hashStream.str();
    getDebugStream(state) << ss << " size " << hexval(size) << "\n";

    onModeSwitch.emit(state, true);
    g_s2e_cache_mode = false;

    for (auto ittp : cache_type_flag_phs) {
        plgState->insert_all_rw_phs(phaddr, 1);
        plgState->insert_type_flag_phs(ittp.first, ittp.second);
        plgState->insert_t0_type_flag_phs(ittp.first, 1);
        if (ittp.second == T3) {
            plgState->inc_readphs(ittp.first, cache_dr_type_size[ittp.second]);
        }
    }

    for (auto itt1 : cache_t1_type_phs) {
        plgState->inc_readphs(itt1.first.first, 0x4);
        plgState->insert_lock_t1_type_flag(itt1.first.first, 1);
        plgState->insert_t1_type_phs(itt1.first, itt1.second.first, std::make_pair(0, itt1.second.second));
    }

    for (auto itpt1 : cache_pt1_type_phs) {
        plgState->inc_readphs(itpt1.first.first, 0x4);
        plgState->insert_pt1_type_flag_phs(itpt1.first, 2);
        plgState->insert_pt1_type_phs(itpt1.first, itpt1.second.first, std::make_pair(0, itpt1.second.second));
    }

    for (auto itt2 : cache_t2_type_phs) {
        plgState->inc_readphs(itt2.first.first, 0x4);
        plgState->insert_lock_t1_type_flag(itt2.first.first, 1);
        plgState->insert_t2_type_flag_phs(itt2.first, T2);
        for (auto itt2it : itt2.second) {
            plgState->insert_t2_type_phs(itt2.first, itt2it.first, itt2it.second);
        }
    }

    for (auto itul : cache_t3_type_phs_backup) {
        for (auto itulit : itul.second) {
            plgState->insert_t3_type_ph_back(itul.first, itulit);
        }
    }

    for (auto itirqs : cache_tirqs_type_phs) {
        if (plgState->get_type_flag_ph_it(std::get<1>(itirqs.first)) == T1) {
            plgState->insert_irq_flag_phs(std::get<1>(itirqs.first), 1);
            for (auto itirqph : itirqs.second) {
                possible_irq_values[itirqs.first].push_back(itirqph); // refill to t3 cache for next fuzzing
            }
        }
    }

    for (auto itirqcs : cache_tirqc_type_phs) {
        if (plgState->get_type_flag_ph_it(itirqcs.first.second) == T1) {
            plgState->insert_irq_flag_phs(itirqcs.first.second, 2);
            for (auto itirqphcs : itirqcs.second) {
                for (auto itirqphc : itirqphcs.second) {
                    for (auto itirqphcit : itirqphc.second) {
                        plgState->insert_tirqc_type_phs(itirqcs.first.first, itirqcs.first.second, itirqphcs.first,
                                                        itirqphc.first, itirqphcit);
                    }
                }
            }
        }
    }

    // only t3 cache
    for (auto ituncaches : cache_all_cache_phs) {
        for (auto ituncache : ituncaches.second) {
            plgState->insert_cachephs(ituncaches.first, ituncache.first, ituncache.second);
        }
    }

    start = time(NULL);
    onStateForkConnection =
        s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &PeripheralModelLearning::onFork));
    onStateSwitchConnection =
        s2e()->getCorePlugin()->onStateSwitch.connect(sigc::mem_fun(*this, &PeripheralModelLearning::onStateSwitch));
    onStateForkDecideConnection = s2e()->getCorePlugin()->onStateForkDecide.connect(
        sigc::mem_fun(*this, &PeripheralModelLearning::onStateForkDecide));
    onInterruptExitonnection = s2e()->getCorePlugin()->onExceptionExit.connect(
        sigc::mem_fun(*this, &PeripheralModelLearning::onExceptionExit));

    if (plgState->get_type_flag_ph_it(phaddr) == T0) {
        if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) {
            irq_crs[state->regs()->getExceptionIndex()][phaddr] = plgState->get_writeph(phaddr);
        }
        getDebugStream() << " T0 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                         << " value = " << hexval(concreteValue) << "\n";
        ConcreteArray concolicValue;
        SymbHwGetConcolicVector(plgState->get_writeph(phaddr), size, concolicValue);
        return state->createSymbolicValue(ss, size * 8, concolicValue);
    } else {
        getDebugStream() << " T1 type ph addr = " << hexval(phaddr) << " pc = " << hexval(pc)
                         << " value = " << hexval(concreteValue) << "\n";
        ConcreteArray concolicValue;
        plgState->insert_type_flag_phs(phaddr, T1);
        plgState->insert_pt1_type_flag_phs(UniquePeripheral(phaddr, pc), 1);
        if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() > 15) { // external irq handle
            possible_irq_srs[std::make_pair(phaddr, pc)] = state->regs()->getExceptionIndex();
            if (find(irq_srs[state->regs()->getExceptionIndex()].begin(),
                     irq_srs[state->regs()->getExceptionIndex()].end(),
                     phaddr) == irq_srs[state->regs()->getExceptionIndex()].end()) {
                irq_srs[state->regs()->getExceptionIndex()].push_back(phaddr);
            }
        }
        SymbHwGetConcolicVector(concreteValue, size, concolicValue);
        return state->createSymbolicValue(ss, size * 8, concolicValue);
    }
}

void PeripheralModelLearning::switchModefromLtoF(S2EExecutionState *state) {
    cache_t2_type_phs.clear();
    cache_pt1_type_phs.clear();
    cache_t3_type_phs.clear();
    cache_tirqc_type_phs.clear();
    cache_tirqs_type_phs.clear();
    cache_type_irqc_flag.clear();
    cache_type_irqs_flag.clear();
    cache_type_flag_phs.clear();
    cache_t1_type_flag_phs.clear();
    cache_t2_type_flag_phs.clear();
    cache_all_cache_phs.clear();
    possible_irq_values.clear();

    onStateForkConnection.disconnect();
    onStateForkDecideConnection.disconnect();
    onStateSwitchConnection.disconnect();
    onInterruptExitonnection.disconnect();
    g_s2e_cache_mode = true;

    // TODO: updatge learning_mode_states in every kill and put the learning mode states to false states to kill
    if (!readKBfromFile(fileName)) {
        getWarningsStream() << "Could not read peripheral regs from cache file" << fileName << "\n";
        exit(-1);
    }
    onModeSwitch.emit(state, false);
    false_type_phs_fork_states.clear();
    for (auto learnings : learning_mode_states) {
        if (learnings != state) {
            getWarningsStream() << "Kill Fork State in learning mode:" << learnings->getID() << "\n";
            false_type_phs_fork_states.push_back(learnings);
        }
    }
    fs = -1;
    learning_mode_states.clear();
    std::string s;
    llvm::raw_string_ostream ss(s);
    ss << "Kill All Fork States in Learning mode before switch to fuzzing mode!" << state->getID() << "\n";
    ss.flush();
    s2e()->getExecutor()->terminateState(*state, s);
}

// only used for no invalid state test version
/*void PeripheralModelLearning::onTerminationDetectionTest(S2EExecutionState *state, bool availablestate, uint64_t
 * tb_num) {*/
// if (availablestate) {
// getDebugStream() << "live state phs save last fork state!! \n";
// end = time(NULL);
// durationtime = durationtime + (end - start);
// getWarningsStream(state) << "Learning time = " << durationtime << "s\n";
// getWarningsStream(state) << "All_search_path_num = " << all_searched_path_map.size()
//<< " All_path_num = " << all_path_map.size() + 1 << "\n";

// getWarningsStream() << "Kill Live Loop State:" << state->getID()
//<< " tb num " << tb_num << "\n";
// g_s2e->getCorePlugin()->onEngineShutdown.emit();
//// Flush here just in case ~S2E() is not called (e.g., if atexit()
//// shutdown handler was not called properly).
// g_s2e->flushOutputStreams();
// exit(0);
//}
//}

// klee::ref<klee::Expr> PeripheralModelLearning::onLearningModeTest(S2EExecutionState *state,
// SymbolicHardwareAccessType type,
// uint64_t address, unsigned size, uint64_t concreteValue) {
// uint32_t pc = state->regs()->getPc();
// std::stringstream ss;
// switch (type) {
// case SYMB_MMIO:
// ss << "iommuread_";
// break;
// case SYMB_DMA:
// ss << "dmaread_";
// break;
// case SYMB_PORT:
// ss << "portread_";
// break;
//}

// ss << hexval(address) << "@" << hexval(pc);
// all_peripheral_no ++;

////uint32_t rand_org = rand();
////uint32_t rand_value = int(((rand_org % 0x7ffe) * 1.0 / 0x7fff) * 4294967295);

//[>if (state->getID() == 0) {<]
////rand_org = 0;
//[>}<]
// uint32_t rand_org = 0;

// getDebugStream(state) << ss.str() << " rand perfer value = " << hexval(rand_org) << "\n";
// ConcreteArray concolicValue;
// SymbHwGetConcolicVector(rand_org, size, concolicValue);
// return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
//}

// void PeripheralModelLearning::onForkTest(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
// const std::vector<klee::ref<klee::Expr>> &newConditions)  {
// for (int k = newStates.size() - 1; k >= 0; --k) {
//// update path map
// if (newStates[k] == state) {
// all_searched_path_map[newStates[k]->getID()] = 1;
//} else {
// all_path_map[newStates[k]->getID()] = 1;
//}
//}
// getWarningsStream(state) << " all_searched_paths = " << all_searched_path_map.size() << " all path = " <<
// all_path_map.size() << "\n";
//}

// void PeripheralModelLearning::onStateForkDecideTest(S2EExecutionState *state, bool *doFork, const
// klee::ref<klee::Expr> &condition, bool *conditionFork) {
// uint32_t rand_org = rand() % 2;
// if (rand_org == 0) {
//*conditionFork = false;
//} else {
//*conditionFork = true;
//}
/*}*/

} // namespace hw
} // namespace plugins
} // namespace s2e
