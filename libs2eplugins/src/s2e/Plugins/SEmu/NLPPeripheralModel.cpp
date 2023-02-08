//
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "NLPPeripheralModel.h"
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/SymbolicHardwareHook.h>
#include <klee/util/ExprUtil.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <sys/shm.h>
//#include <time.h>
#include <algorithm>
#include <random>

using namespace klee;
namespace s2e {
namespace plugins {

static const boost::regex SymbolicPeripheralRegEx("v\\d+_iommuread_(.+)_(.+)_(.+)", boost::regex::perl);
S2E_DEFINE_PLUGIN(NLPPeripheralModel, "NLP Peripheral Model", "NLPPeripheralModel");

class NLPPeripheralModelState : public PluginState {
private:
    RegMap state_map;
    std::map<int, int> exit_interrupt; // interrupt id, num
    std::map<uint32_t, uint32_t> interrupt_freq;
    uint32_t fork_point_count;
    bool instruction;
    uint32_t cur_dp_addr;

public:
    NLPPeripheralModelState() {
        interrupt_freq.clear();
        fork_point_count = 0;
        instruction = false;
    }

    virtual ~NLPPeripheralModelState() {
    }

    static PluginState *factory(Plugin *, S2EExecutionState *) {
        return new NLPPeripheralModelState();
    }

    NLPPeripheralModelState *clone() const {
        return new NLPPeripheralModelState(*this);
    }

    bool pending_interrupt() {
        for (auto irq : exit_interrupt) {
            if (irq.second > 0 && interrupt_freq[irq.first] < 2) {
                return true;
            }
        }
        return false;
    }
    bool get_exit_interrupt(uint32_t num) {
        return exit_interrupt[num] > 0;
    }

    void set_exit_interrupt(uint32_t num, int cur) {
        exit_interrupt[num] += cur;
    }

    RegMap get_state_map() {
        return state_map;
    }

    void insert_reg_map(uint32_t phaddr, Reg reg) {
        state_map[phaddr] = reg;
    }

    void write_ph_value(uint32_t phaddr, uint32_t value) {
        state_map[phaddr].cur_value = value;
    }

    uint32_t get_ph_value(uint32_t phaddr) {
        return state_map[phaddr].cur_value;
    }

    bool check_instruction() {
        return instruction;
    }
    void receive_instruction(uint32_t phaddr) {
        if (instruction && state_map[phaddr].dr.r_value.empty()) {
            instruction = false;
            state_map[phaddr].dr.t_value = 0;
        }
    }

    void write_dr_value(uint32_t phaddr, uint32_t value, uint32_t width) {
        state_map[phaddr].dr.t_value = (state_map[phaddr].dr.t_value << width * 8) + value;
        state_map[phaddr].dr.t_size = 0; // width;
    }

    void rx_push_to_fix_size(uint32_t phaddr, int size) {
        if (state_map[phaddr].dr.r_value.size() < size) {
            for (unsigned j = 0; j < size - state_map[phaddr].dr.r_value.size(); j++) {
                state_map[phaddr].dr.r_value.push(0);
            }
        }
    }

    void clear_rx(uint32_t phaddr) {
        state_map[phaddr].dr.r_value = {};
        state_map[phaddr].dr.r_size = 0;
    }

    uint8_t get_dr_value(uint32_t phaddr, uint32_t width) {
        width *= 8;
        state_map[phaddr].dr.r_size -= width;
        if (state_map[phaddr].dr.r_value.empty()) {
            state_map[phaddr].dr.r_size = 0;
            return 0;
        }
        uint8_t cur_value = state_map[phaddr].dr.r_value.front();
        state_map[phaddr].dr.r_value.pop();
        return cur_value;
    }

    uint8_t get_rx_size(uint32_t phaddr) {
        return state_map[phaddr].dr.r_size;
    }

    void hardware_write_to_receive_buffer(uint32_t phaddr, std::queue<uint8_t> value, uint32_t width) {
        if (!state_map[phaddr].dr.r_value.empty())
            return;
        state_map[phaddr].dr.r_size = width * 8;
        // state_map[phaddr].front_left = 8;     //front size
        state_map[phaddr].dr.r_value = value;
    }

    void inc_irq_freq(uint32_t irq_no) {
        interrupt_freq[irq_no]++;
    }

    uint32_t get_irq_freq(uint32_t irq_no) {
        return interrupt_freq[irq_no];
    }

    void clear_irq_freq(uint32_t irq_no) {
        interrupt_freq[irq_no] = 0;
    }

    std::map<uint32_t, uint32_t> get_irqs_freq() {
        return interrupt_freq;
    }

    void inc_fork_count() {
        fork_point_count++;
    }

    uint32_t get_fork_point_count() {
        return fork_point_count;
    }

    // cur description loc
    void insert_cur_dp_addr(uint32_t mem_addr) {
        cur_dp_addr = mem_addr;
    }

    uint32_t get_cur_dp_addr() {
        return cur_dp_addr;
    }
};

// initialize
bool NLPPeripheralModel::parseConfig(void) {
    ConfigFile *cfg = s2e()->getConfig();
    hw::PeripheralMmioRanges nlpphs;
    std::stringstream ss;
    ss << getConfigKey();
    getDebugStream() << "config " << ss.str() << "\n";
    if (!parseRangeList(cfg, ss.str() + ".nlp_mmio", nlpphs)) {
        return false;
    }

    for (auto nlpph : nlpphs) {
        getInfoStream() << "Adding nlp ph range " << hexval(nlpph.first) << " - " << hexval(nlpph.second) << "\n";
        nlp_mmio.push_back(nlpph);
    }

    return true;
}

template <typename T> bool NLPPeripheralModel::parseRangeList(ConfigFile *cfg, const std::string &key, T &result) {
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
            getWarningsStream() << "Could not parse start address: " << ss.str() + "[1]"
                                << "\n";
            return false;
        }

        uint64_t end = cfg->getInt(ss.str() + "[2]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse end address: " << ss.str() + "[2]"
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

void NLPPeripheralModel::initialize() {
    NLPfileName = s2e()->getConfig()->getString(getConfigKey() + ".NLPfileName", "all.txt");
    getDebugStream() << "NLP peripheral model file name is " << NLPfileName << "\n";
    if (!parseConfig()) {
        getWarningsStream() << "Could not parse NLP range config\n";
        exit(-1);
    }

    bool ok;
    fork_point = s2e()->getConfig()->getInt(getConfigKey() + ".forkPoint", 0x0, &ok);
    getInfoStream() << "set fork_point phaddr = " << hexval(fork_point) << "\n";
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &NLPPeripheralModel::onTranslateBlockStart));
    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &NLPPeripheralModel::onTranslateBlockEnd));
    s2e()->getCorePlugin()->onExceptionExit.connect(sigc::mem_fun(*this, &NLPPeripheralModel::onExceptionExit));
    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &NLPPeripheralModel::onFirmwareFork));
    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &NLPPeripheralModel::onStatistics));

    onExternalHardwareSignalConnection = s2e()->getPlugin<ExternalHardwareSignal>();
    onExternalHardwareSignalConnection->onReadUpdate.connect(
        sigc::mem_fun(*this, &NLPPeripheralModel::onPeripheralRead));
    onExternalHardwareSignalConnection->onWriteUpdate.connect(
        sigc::mem_fun(*this, &NLPPeripheralModel::onPeripheralWrite));
    onExternalHardwareSignalConnection->onSignalUpdate.connect(
        sigc::mem_fun(*this, &NLPPeripheralModel::onUpdateBySignals));

    rw_count = 0;
    // srand(time(NULL));
}

// read data
bool NLPPeripheralModel::readNLPModelfromFile(S2EExecutionState *state, std::string &fileName) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    std::ifstream fNLP;
    std::string line;
    fNLP.open(fileName, std::ios::in);
    if (!fNLP) {
        getWarningsStream() << "Could not open cache nlp file: " << fileName << "\n";
        exit(-1);
        return false;
    }

    std::string peripheralcache;
    while (getline(fNLP, peripheralcache)) {
        if (peripheralcache == "==")
            break;
        Reg reg;
        if (getMemo(peripheralcache, reg)) {
            plgState->insert_reg_map(reg.phaddr, reg);
        } else {
            return false;
        }
    }

    int _idx = 0;
    while (getline(fNLP, peripheralcache)) {
        if (peripheralcache == "==")
            break;
        if (peripheralcache == "--") {
            continue;
        }
        EquList trigger;
        EquList action;
        if (getTApairs(peripheralcache, trigger, action)) {
            trigger[0].id = ++_idx;
            auto rule = make_pair(trigger, action);
            EquList tmp;
            tmp.insert(tmp.end(), trigger.begin(), trigger.end());
            tmp.insert(tmp.end(), action.begin(), action.end());
            for (auto &equ : tmp) {
                if (equ.eq == "*")
                    continue;
                recordRule(equ.a1.phaddr, rule);
                if (equ.type_a2 == "F")
                    recordRule(equ.a2_field.phaddr, rule);
            }
        } else {
            return false;
        }
    }

    while (getline(fNLP, peripheralcache)) {
        if (peripheralcache == "==")
            break;
        if (peripheralcache == "--")
            continue;

        Flag count;
        if (extractFlag(peripheralcache, count)) {
            count.id = ++_idx;
            all_counters[count.a1.phaddr].push_back(count);
        } else {
            return false;
        }
    }

    while (getline(fNLP, peripheralcache)) {
        if (peripheralcache == "==")
            break;
        DMA dma;
        if (extractDMA(peripheralcache, dma)) {
            all_dmas.push_back(dma);
        } else {
            return false;
        }
    }

    onEnableISER.emit(state, &irq_no);
    return true;
}

bool NLPPeripheralModel::getMemo(std::string &peripheralcache, Reg &reg) {
    getDebugStream() << peripheralcache << "\n";
    std::vector<std::string> v;
    SplitString(peripheralcache, v, "_");
    if (v[0].find("E") != std::string::npos) {
        v[0] = v[0].substr(0, 1);
        reg.is_eth = true;
    }
    reg.type = v[0];
    reg.phaddr = std::stoull(v[1].c_str(), NULL, 16);
    reg.reset = std::stoull(v[2].c_str(), NULL, 16);
    reg.width = std::stoull(v[3].c_str(), NULL, 10);
    reg.data_width = std::stoull(v[4].c_str(), NULL, 10);
    reg.cur_value = reg.reset;
    if (v[0] == "R" || v[0] == "T") {
        reg.dr = DataReg();
        getDebugStream() << "data register: " << hexval(reg.phaddr) << "\n";
        data_register.insert(reg.phaddr);
    }

    // reg.r_value = new std::queue<uint8_t>();
    getDebugStream() << "type = " << reg.type << " phaddr = " << hexval(reg.phaddr)
                     << " reset value = " << hexval(reg.reset) << " width = " << v[3] << " (int)" << reg.width
                     << " data_width = " << reg.data_width << " eth = " << reg.is_eth << " dr = " << reg.dr.r_size
                     << "\n";
    return true;
}

void NLPPeripheralModel::SplitString(const std::string &s, std::vector<std::string> &v, const std::string &c) {
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

void NLPPeripheralModel::SplitStringToInt(const std::string &s, std::vector<long> &v, const std::string &c, int dtype) {
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while (std::string::npos != pos2) {
        v.push_back(std::strtol(s.substr(pos1, pos2 - pos1).c_str(), NULL, dtype));
        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if (pos1 != s.length()) {
        v.push_back(std::strtol(s.substr(pos1).c_str(), NULL, dtype));
    }
}

bool NLPPeripheralModel::getTApairs(std::string &peripheralcache, EquList &trigger, EquList &action) {
    getDebugStream() << peripheralcache << "\n";
    std::vector<std::string> v;
    SplitString(peripheralcache, v, "->");
    std::string trigger_str = v[0];
    std::string action_str = v[1];
    std::vector<std::string> tmp;
    SplitString(action_str, tmp, "&IRQ");
    int32_t interrupt = -1;
    bool is_irq = true;
    if (tmp.size() == 1) {
        is_irq = false;
        tmp.clear();
        SplitString(action_str, tmp, "&DMA");
    }
    if (tmp.size() == 2) {
        interrupt = std::stoi(tmp[1].substr(1, tmp[1].size() - 1).c_str(), NULL, 10);
        action_str = tmp[0];
    }

    bool trigger_rel = true, action_rel = true;
    if (trigger_str.find("|", 0) != std::string::npos) {
        trigger_rel = false;
    }

    if (action_str.find("|", 0) != std::string::npos) {
        action_rel = false;
    }
    getDebugStream() << " trigger = " << trigger_str << " action = " << action_str << "\n";

    bool res = extractEqu(trigger_str, trigger, trigger_rel, true) && extractEqu(action_str, action, action_rel, false);
    if (interrupt != -1) {
        if (is_irq)
            action.back().interrupt = interrupt;
        else
            action.back().dma_irq = interrupt;
        getDebugStream() << "IRQ interrupt = " << action.back().interrupt << "\n";
    }
    return res;
}

std::pair<std::string, uint32_t> NLPPeripheralModel::getAddress(std::string &addr) {
    if (addr[0] != '0') {
        return std::make_pair(addr.substr(0, 2), std::stoull(addr.substr(2, addr.size() - 2).c_str(), NULL, 16));
    } else {
        uint32_t phaddr = std::stoull(addr.c_str(), NULL, 16);
        if (data_register.find(phaddr) != data_register.end())
            return std::make_pair("V" + regs[phaddr].type, phaddr);
        else
            return std::make_pair("*", phaddr);
    }
}

std::vector<long> NLPPeripheralModel::getBits(std::string &bits) {
    std::vector<long> res;
    if (bits == "*")
        return {-1};
    else {
        SplitStringToInt(bits, res, "/", 10);
        return res;
    }
}

bool NLPPeripheralModel::extractEqu(std::string &peripheralcache, EquList &vec, bool rel, bool is_trigger) {
    boost::smatch what;
    getDebugStream() << peripheralcache << "\n";

    while (boost::regex_search(peripheralcache, what, TARegEx)) {
        std::string equ_str = what[0];
        getDebugStream() << "equ_str: " << equ_str << "\n";
        std::vector<std::string> v;
        SplitString(equ_str, v, ",");
        Equation equ;
        equ.rel = rel;
        equ.dma_irq = -1;
        equ.interrupt = -1;
        if (v[0] == "O") {
            equ.type_eq = "O";
            equ.a1.bits = {-1};
            equ.eq = "*";
            equ.type_a2 = "*";
        } else {
            uint8_t start = 0;
            if (is_trigger) {
                equ.type_eq = v[start++];
            }
            auto tmp = getAddress(v[start++]);
            equ.a1.type = tmp.first;
            equ.a1.phaddr = tmp.second;
            equ.a1.bits = getBits(v[start++]);
            equ.eq = v[start++];
            std::string value = v[start++];
            if (value.find("0x") != std::string::npos) {
                equ.type_a2 = "F";
                tmp = getAddress(value);
                equ.a2_field.type = tmp.first;
                equ.a2_field.phaddr = tmp.second;
                if (start < v.size())
                    equ.a2_field.bits = getBits(v[start]);
            } else if (value != "*") {
                equ.type_a2 = "V";
                equ.a2_value = std::stoull(value.c_str(), NULL, 2);
            }
        }
        getDebugStream() << " equ.id: " << equ.id << " type_eq: " << equ.type_eq << " a1.type: " << equ.a1.type
                         << " a1 phaddr: " << hexval(equ.a1.phaddr) << " a1.bits: " << equ.a1.bits[0]
                         << " eq: " << equ.eq << " equ.type_a2: " << equ.type_a2
                         << " equ.a2.type: " << equ.a2_field.type << " equ.a2.phaddr " << hexval(equ.a2_field.phaddr)
                         << " equ.a2.bits: " << equ.a2_field.bits[0] << " equ.a2.value: " << equ.a2_value
                         << " interrupt: " << equ.interrupt << " dma_irq: " << equ.dma_irq << "\n";

        vec.push_back(equ);
        peripheralcache = what.suffix();
    }
    return true;
}

void NLPPeripheralModel::recordRule(uint32_t addr, TA &rule) {
    all_rules[rule.first[0].type_eq][addr].push_back(rule);
}

bool NLPPeripheralModel::extractFlag(std::string &peripheralcache, Flag &flag) {
    getDebugStream() << peripheralcache << "\n";
    std::vector<std::string> v2, v;
    SplitString(peripheralcache, v2, "->");
    SplitString(v2[1], v, ",");
    auto tmp = getAddress(v[0]);
    flag.a1.type = tmp.first;
    flag.a1.phaddr = tmp.second;
    flag.a1.bits = getBits(v[1]);
    if (v[3].find("/") != std::string::npos) {
        flag.tag = Rand;
        SplitStringToInt(v[3], flag.value, "/", 16);
    } else if (v[3].find("|") != std::string::npos) {
        flag.tag = Flip;
        flag.value = {std::strtol(v[3].substr(1, v[3].size() - 1).c_str(), NULL, 16)};
    } else if (v[3].find("^") != std::string::npos) {
        flag.tag = Counter;
        flag.value = {std::strtol(v[3].substr(1, v[3].size() - 1).c_str(), NULL, 16)};
    } else {
        flag.tag = Fix;
        flag.value = {std::strtol(v[3].c_str(), NULL, 16)};
    }
    getDebugStream() << "extractFlag  " << hexval(flag.a1.phaddr) << " " << flag.a1.bits[0] << " " << flag.tag << " "
                     << flag.value[0] << "\n";
    return true;
}

bool NLPPeripheralModel::extractDMA(std::string &peripheralcache, DMA &dma) {
    getDebugStream() << peripheralcache << "\n";
    std::vector<std::string> v;
    SplitString(peripheralcache, v, ";");
    dma.dma_irq = std::stoull(v[0].c_str(), NULL, 10);
    dma.state = 0;

    std::vector<std::string> twomemory;
    SplitString(v[1], twomemory, "|");
    std::vector<std::string> field;
    SplitString(twomemory[0], field, ",");
    Field memory;
    memory.phaddr = std::stoull(field[1].c_str(), NULL, 16);
    memory.type = field[0];
    memory.bits = {-1};
    dma.memo_field = memory;

    field.clear();
    SplitString(v[2], field, ",");
    Field peri;
    peri.phaddr = std::stoull(field[1].c_str(), NULL, 16);
    peri.type = field[0];
    peri.bits = {-1};
    dma.peri_field = peri;

    field.clear();
    SplitString(v[4], field, ",");
    Field htif;
    htif.phaddr = std::stoull(field[1].c_str(), NULL, 16);
    htif.type = field[0];
    SplitStringToInt(field[2], htif.bits, "/", 10);
    dma.HTIF = htif;

    field.clear();
    SplitString(v[5], field, ",");
    Field tcif;
    tcif.phaddr = std::stoull(field[1].c_str(), NULL, 16);
    tcif.type = field[0];
    SplitStringToInt(field[2], tcif.bits, "/", 10);
    dma.TCIF = tcif;

    field.clear();
    Field gif;
    gif.type = "N/A";
    SplitString(v[6], field, ",");
    if (!field.empty()) {
        gif.phaddr = std::stoull(field[1].c_str(), NULL, 16);
        gif.type = field[0];
        SplitStringToInt(field[2], gif.bits, "/", 10);
    }
    dma.GIF = gif;
    return true;
}

// access
void NLPPeripheralModel::hardware_write_to_receive_buffer(S2EExecutionState *state, uint32_t phaddr) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    getInfoStream() << " write random dr value e.g., 0x1!\n";
    std::queue<uint8_t> tmp;
    for (int i = 0; i < 1; ++i) {
        tmp.push(0x1);
    }
    if (phaddr != 0) {
        plgState->hardware_write_to_receive_buffer(phaddr, tmp, tmp.size());
        deal_rule_RWVB(state, phaddr, "B");
        return;
    }
    for (auto _phaddr : data_register) {
        plgState->hardware_write_to_receive_buffer(_phaddr, tmp, tmp.size());
        deal_rule_RWVB(state, _phaddr, "B");
    }
}

std::pair<uint32_t, uint32_t> NLPPeripheralModel::AddressCorrection(S2EExecutionState *state, uint32_t phaddr) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    RegMap state_map = plgState->get_state_map();
    if (state_map.find(phaddr) != state_map.end())
        return {phaddr, 0};
    auto uppper_node = state_map.upper_bound(phaddr);
    // uint32_t new_phaddr = phaddr & 0xFFFFFFFC;
    if (uppper_node != state_map.begin())
        uppper_node--;
    uint32_t new_phaddr = uppper_node->first;
    uint32_t offset = (phaddr - new_phaddr) * 8;
    if (offset != 0)
        getInfoStream() << "correction " << hexval(phaddr) << " new correction " << hexval(new_phaddr) << " \n";
    return {new_phaddr, offset};
}

void NLPPeripheralModel::onPeripheralRead(S2EExecutionState *state, SymbolicHardwareAccessType type, uint32_t phaddr,
                                          unsigned size, uint32_t *NLPSymbolicValue, bool *createSymFlag,
                                          std::stringstream *ss) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    *ss << "_" << hexval(size);
    rw_count++;
    if (rw_count == 1) {
        readNLPModelfromFile(state, NLPfileName);
        hardware_write_to_receive_buffer(state);
    }
    auto correction = AddressCorrection(state, phaddr);
    phaddr = correction.first;
    *createSymFlag = true;

    deal_rule_O(state);
    deal_rule_flag(state, phaddr);
    deal_rule_RWVB(state, phaddr, "R");
    RegMap state_map = plgState->get_state_map();
    if (data_register.find(phaddr) != data_register.end()) {
        // unauthorized access check
        if (ExistInMMIO(phaddr) && checked_SR == false) {
            getInfoStream() << "unauthorized READ access to data register: " << hexval(phaddr)
                            << "pc = " << hexval(state->regs()->getPc()) << "\n";
            if (read_unauthorized_freq.find(phaddr) == read_unauthorized_freq.end()) {
                std::set<uint64_t> tmp;
                read_unauthorized_freq[phaddr] = tmp;
            }
            read_unauthorized_freq[phaddr].insert(state->regs()->getPc());
        }
        *createSymFlag = false;
        size = state_map[phaddr].width / 8;
        std::vector<unsigned char> data;
        for (uint32_t i = 0; i < size; i++) {
            data.push_back(plgState->get_dr_value(phaddr, 1));
        }
        if (size == 4) {
            *NLPSymbolicValue =
                data[0] | ((uint32_t) data[1] << 8) | ((uint32_t) data[2] << 16) | ((uint32_t) data[3] << 24);
        } else if (size == 2) {
            *NLPSymbolicValue = data[0] | ((uint32_t) data[1] << 8);
        } else {
            *NLPSymbolicValue = data[0];
        }
        plgState->receive_instruction(phaddr);
        getInfoStream() << "Read data register " << hexval(phaddr) << " width " << size
                        << " rxsize = " << (uint32_t) plgState->get_rx_size(phaddr)
                        << " pc = " << hexval(state->regs()->getPc()) << " value " << hexval(*NLPSymbolicValue) << " "
                        << (uint32_t) data[0] << " " << (uint32_t) data[1] << " " << (uint32_t) data[2] << " "
                        << (uint32_t) data[3] << "\n";
        deal_rule_RWVB(state, phaddr, "B");
    } else {
        *NLPSymbolicValue = plgState->get_ph_value(phaddr);
    }

    checked_SR = false;
    if (state_map[phaddr].type == "S") {
        checked_SR = true;
    }
    deal_rule_RWVB(state, phaddr, "V");
    getDebugStream() << "correction " << hexval(phaddr) << " value " << *NLPSymbolicValue << " \n";
    if (correction.second != 0) {
        *NLPSymbolicValue = *NLPSymbolicValue >> correction.second;
    }
    getDebugStream() << "Read phaddr " << hexval(phaddr) << " value " << hexval(*NLPSymbolicValue) << " \n";
    if (ExistInMMIO(phaddr)) {
        onFirmwareRead.emit(state, phaddr, state_map[phaddr].cur_value);
    }
}

void NLPPeripheralModel::onPeripheralWrite(S2EExecutionState *state, SymbolicHardwareAccessType type, uint32_t phaddr,
                                           uint32_t writeconcretevalue) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    rw_count++;
    if (rw_count == 1) {
        readNLPModelfromFile(state, NLPfileName);
        hardware_write_to_receive_buffer(state);
    }
    auto correction = AddressCorrection(state, phaddr);
    phaddr = correction.first;
    if (correction.second != 0) {
        writeconcretevalue = writeconcretevalue << correction.second;
    }

    deal_rule_O(state);
    deal_rule_flag(state, phaddr);
    deal_rule_RWVB(state, phaddr, "W");
    RegMap state_map = plgState->get_state_map();
    if (data_register.find(phaddr) != data_register.end()) {
        // unauthorized access check
        if (ExistInMMIO(phaddr) && checked_SR == false) {
            getInfoStream() << "unauthorized WRITE access to data register: " << hexval(phaddr)
                            << " pc = " << hexval(state->regs()->getPc()) << "\n";
            if (write_unauthorized_freq.find(phaddr) == write_unauthorized_freq.end()) {
                std::set<uint64_t> tmp;
                tmp.insert(state->regs()->getPc());
                write_unauthorized_freq[phaddr] = tmp;
            } else
                write_unauthorized_freq[phaddr].insert(state->regs()->getPc());
        }
        plgState->write_dr_value(phaddr, writeconcretevalue, 1);
        getInfoStream() << "Write to data register " << hexval(phaddr)
                        << " value: " << hexval(writeconcretevalue)
                        << " cur dr: " << hexval(state_map[phaddr].dr.t_value) << " \n";
        deal_rule_RWVB(state, phaddr, "B");
    } else {
        plgState->write_ph_value(phaddr, writeconcretevalue);
        getInfoStream() << "Write to phaddr " << hexval(phaddr) << " value: " << hexval(writeconcretevalue) << " \n";
    }

    deal_rule_RWVB(state, phaddr, "V");
    if (ExistInMMIO(phaddr)) {
        onFirmwareWrite.emit(state, phaddr, state_map[phaddr].cur_value);
    }
}

// update graph
void NLPPeripheralModel::take_action(S2EExecutionState *state, EquList &actions, bool buffer_related = false) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    RegMap state_map = plgState->get_state_map();
    std::vector<uint32_t> irqs;
    for (auto &equ : actions) {
        uint32_t value1 = get_reg_value(state, state_map, equ.a1);
        getDebugStream() << "take action equ.id: " << equ.id << " type_eq: " << equ.type_eq
                         << " a1.type: " << equ.a1.type << " a1 phaddr: " << hexval(equ.a1.phaddr)
                         << " a1.bits: " << equ.a1.bits[0] << " eq: " << equ.eq << " equ.type_a2: " << equ.type_a2
                         << " equ.a2.type: " << equ.a2_field.type << " equ.a2.value: " << equ.a2_value
                         << " interrupt: " << equ.interrupt << " dma_irq: " << equ.dma_irq << "\n";

        uint32_t value2 = 0;
        if (equ.type_a2 == "F") {
            value2 = get_reg_value(state, state_map, equ.a2_field);
            getDebugStream() << "get by address, phaddr" << hexval(equ.a2_field.phaddr) << " bits "
                             << equ.a2_field.bits[0] << " " << value2 << "\n";
        } else if (equ.type_a2 == "V") {
            value2 = equ.a2_value;
        } else {
            getWarningsStream() << "ERROR: equ a2 value: " << equ.type_a2 << " phaddr " << hexval(equ.a2_field.phaddr)
                                << " bits " << equ.a2_field.bits[0] << " " << value2 << "\n";
        }
        if (value1 != value2) {
            if (data_register.find(equ.a1.phaddr) == data_register.end()) {
                set_reg_value(state, state_map, equ.a1, value2);
                getDebugStream() << "Action: phaddr =  " << hexval(equ.a1.phaddr) << " updated bit = " << equ.a1.bits[0]
                                 << " value = " << hexval(state_map[equ.a1.phaddr].cur_value) << " a2 = " << value2
                                 << "\n";
            } else if (equ.a1.type.find("R") != std::string::npos) {
                getDebugStream() << "set receive value : phaddr =  " << hexval(equ.a1.phaddr)
                                 << " updated bit = " << equ.a1.bits[0]
                                 << " value = " << hexval(state_map[equ.a1.phaddr].cur_value) << " a2 = " << value2
                                 << "\n";
                state_map[equ.a1.phaddr].dr.r_size = value2;
            } else if (equ.a1.type.find("T") != std::string::npos) {
                getDebugStream() << "set transmit value : phaddr =  " << hexval(equ.a1.phaddr)
                                 << " updated bit = " << equ.a1.bits[0]
                                 << " value = " << hexval(state_map[equ.a1.phaddr].cur_value) << " a2 = " << value2
                                 << "\n";
                state_map[equ.a1.phaddr].dr.t_size = value2;
            } else {
                getWarningsStream() << "ERROR: unknow a1 type: " << equ.a1.type << " phaddr: " << hexval(equ.a1.phaddr)
                                    << " updated bit = " << equ.a1.bits[0]
                                    << " value = " << hexval(state_map[equ.a1.phaddr].cur_value) << " a2 = " << value2
                                    << "\n";
                exit(-1);
            }
            plgState->insert_reg_map(equ.a1.phaddr, state_map[equ.a1.phaddr]);
            buffer_related = true;
        }
        getDebugStream() << "equ.interrupt = " << equ.interrupt
                         << " exit_inter = " << plgState->get_exit_interrupt(equ.interrupt) << "\n";

        if (buffer_related)
            deal_rule_RWVB(state, equ.a1.phaddr, "V");
        // skip if the irq is triggered by the phaddr that is in nlp_mmio
        if (equ.interrupt == -1 || !ExistInMMIO(equ.a1.phaddr))
            continue;

        // all mode, if the irq is not triggered, emit the irq. if successful emited, record the irq and wait for
        // exiting
        if (!plgState->get_exit_interrupt(equ.interrupt)) {
            if (equ.a1.type == "D") {
                getInfoStream() << "symbolic version unsupport for dma channel dignose \n";
            } else
                irqs.push_back(equ.interrupt);
        }
    }

    if (irqs.size() > 1) {
        std::shuffle(std::begin(irqs), std::end(irqs), std::default_random_engine());
    }
    for (auto &interrupt : irqs) {
        if (plgState->get_exit_interrupt(interrupt))
            continue;
        if (!EmitIRQ(state, interrupt)) {
            untriggered_irq.insert(interrupt);
        }
    }
}

void NLPPeripheralModel::deal_rule_O(S2EExecutionState *state) {
    for (auto &O_rules : all_rules["O"]) {
        for (auto &rule : O_rules.second)
            take_action(state, rule.second);
    }
}

uint32_t NLPPeripheralModel::get_reg_value(S2EExecutionState *state, RegMap &state_map, Field &a) {
    uint32_t res, phaddr = 0;
    uint32_t cur_value = 0;
    std::vector<long> bits;
    int start = 0;
    if (a.type.find("T") != std::string::npos) {
        return state_map[a.phaddr].dr.t_size;
    } else if (a.type.find("R") != std::string::npos) {
        return state_map[a.phaddr].dr.r_size;
    } else if (a.type == "L") {
        if (a.bits[0] >= 32) {
            for (auto b : a.bits) {
                bits.push_back(b % 32);
            }
            start = a.bits[0] / 32 * 32;
        } else
            bits = a.bits;
        phaddr = state_map[a.phaddr].cur_value;
        state->mem()->read(phaddr + start, &cur_value, sizeof(cur_value));
    } else {
        phaddr = a.phaddr;
        bits = a.bits;
        cur_value = state_map[phaddr].cur_value;
    }
    // getDebugStream() << "get_reg_value phaddr " << hexval(phaddr) << " cur_value " << hexval(cur_value) << "\n";
    if (bits[0] == -1) {
        return cur_value;
    } else {
        res = 0;
        for (int i = 0; i < bits.size(); ++i) {
            int tmp = bits[i];
            res = (res << 1) + (cur_value >> tmp & 1);
        }
    }
    return res;
}

void NLPPeripheralModel::set_reg_value(S2EExecutionState *state, RegMap &state_map, Field &a, uint32_t value) {
    uint32_t phaddr, cur_value;
    std::vector<long> bits;
    int start = 0;
    if (a.type == "L") {
        if (a.bits[0] >= 32) {
            for (auto b : a.bits) {
                bits.push_back(b % 32);
            }
            start = a.bits[0] / 32 * 32;
        } else
            bits = a.bits;
        phaddr = state_map[a.phaddr].cur_value;
        state->mem()->read(phaddr + start, &cur_value, sizeof(cur_value));
    } else {
        phaddr = a.phaddr;
        cur_value = state_map[phaddr].cur_value;
        bits = a.bits;
    }
    for (int i = 0; i < bits.size(); ++i) {
        int tmp = bits[i];
        int a2 = (value >> (bits.size() - 1 - i)) & 1;
        if (a2 == 1) {
            cur_value |= (1 << tmp);
        } else {
            cur_value &= ~(1 << tmp);
        }
    }
    if (a.type == "L") {
        state->mem()->write(phaddr + start, &cur_value, sizeof(cur_value));
    } else {
        getDebugStream() << "set_reg_value phaddr " << hexval(phaddr)
                         << " cur value:" << hexval(state_map[phaddr].cur_value) << "\n";
        if (bits[0] == -1) {
            state_map[phaddr].cur_value = value;
        } else {
            state_map[phaddr].cur_value = cur_value;
        }
        if (ExistInMMIO(phaddr)) {
            onHardwareWrite.emit(state, phaddr, state_map[phaddr].cur_value);
        }
        getDebugStream() << "new value " << hexval(state_map[phaddr].cur_value) << "\n";
    }
}

bool NLPPeripheralModel::ExistInMMIO(uint32_t tmp) {
    bool check = false;
    for (auto &nlpph : nlp_mmio) {
        if (tmp >= nlpph.first && tmp <= nlpph.second) {
            check = true;
            break;
        }
    }
    return check;
}

bool NLPPeripheralModel::EmitIRQ(S2EExecutionState *state, int irq) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    bool irq_triggered = false;
    onExternalInterruptEvent.emit(state, irq, &irq_triggered);
    if (irq_triggered) {
        getInfoStream() << "SUCCESS! emit irq: " << irq << "\n";
        plgState->inc_irq_freq(irq);
        plgState->set_exit_interrupt(irq, true);
    }
    getInfoStream() << "emit irq DATA IRQ Action trigger interrupt freq = " << plgState->get_irq_freq(irq)
                    << " exit_interrupt = " << plgState->get_exit_interrupt(irq) << " irq = " << irq << "\n";
    return irq_triggered;
}

void NLPPeripheralModel::deal_rule_RWVB(S2EExecutionState *state, uint32_t address, std::string rule_type) {
    if (all_rules[rule_type].find(address) == all_rules[rule_type].end()) {
        getDebugStream() << "not find address: " << hexval(address) << " rule type: " << rule_type << "\n";
        return;
    }
    getDebugStream() << "find address: " << hexval(address) << " rule type: " << rule_type << "\n";

    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    RegMap state_map = plgState->get_state_map();

    auto rules = all_rules[rule_type][address];
    for (auto &rule : rules) {
        bool check = true;
        for (auto &trigger : rule.first) {
            if ((rule_type == "R" || rule_type == "W")) {
                if (trigger.a1.phaddr == address)
                    continue;
                else {
                    check = false;
                    break;
                }
            }
            uint32_t value1 = get_reg_value(state, state_map, trigger.a1);
            getDebugStream() << "looking for trigger: " << hexval(trigger.a1.phaddr) << " bits " << trigger.a1.bits[0]
                             << "\n";
            uint32_t value2;
            if (trigger.type_a2 == "F") {
                value2 = get_reg_value(state, state_map, trigger.a2_field);
                getDebugStream() << "get by address, phaddr" << hexval(trigger.a2_field.phaddr) << " bits "
                                 << trigger.a2_field.bits[0] << " " << value2 << "\n";
            } else if (trigger.type_a2 == "V") {
                value2 = trigger.a2_value;
                getDebugStream() << "get by value, result: " << value1 << " new value " << value2 << " eq "
                                 << trigger.eq << " " << compare(value1, trigger.eq, value2) << "\n";
            } else {
                value2 = 0;
                getWarningsStream() << "ERROR: equ a2 value: " << trigger.type_a2 << "\n";
            }
            if (!compare(value1, trigger.eq, value2)) {
                check = false;
                break;
            }
        }
        if (check)
            take_action(state, rule.second, rule_type == "B");
    }
}

bool NLPPeripheralModel::compare(uint32_t a1, std::string &sym, uint32_t a2) {
    // 1:= ; 2:>; 3:<; 4:>=; 5:<=
    if (sym == "*")
        return false;
    if (sym == "=")
        return a1 == a2;
    if (sym == ">")
        return a1 > a2;
    if (sym == "<")
        return a1 < a2;
    if (sym == ">=")
        return a1 >= a2;
    if (sym == "<=")
        return a1 <= a2;
    return false;
}

void NLPPeripheralModel::deal_rule_flag(S2EExecutionState *state, uint32_t phaddr) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    RegMap state_map = plgState->get_state_map();
    if (rw_count > 1) {
        for (auto &flags : all_counters) {
            for (auto &flag : flags.second) {
                uint32_t value1_bits = get_reg_value(state, state_map, flag.a1);
                uint32_t value2;
                if (flag.tag == Rand) {
                    if (flag.value.size() > 1 && flag.value[1] > 0xf) {
                        value2 = rand() % 0xffffffff;
                    } else {
                        value2 = flag.value[std::rand() % flag.value.size()];
                    }
                    // getInfoStream() << hexval(flag.a1.phaddr) << "rand value old  " << value1_bits << " new " <<
                    // value2 << "\n";
                } else if (flag.tag == Flip) {
                    value2 = value1_bits ^ 1;
                    // getDebugStream() << hexval(flag.a1.phaddr) << "flip value old  " << value1_bits << " new " <<
                    // value2 << "\n";
                } else if (flag.tag == Counter) {
                    value2 = ((value1_bits << 1) + 1) % flag.value[0];
                    // getDebugStream() << hexval(flag.a1.phaddr) << "count value old  " << value1_bits << " new " <<
                    // value2 << "\n";
                } else {
                    value2 = flag.value[0];
                    // getDebugStream() << hexval(flag.a1.phaddr) << "fix value old  " << value1_bits << " new " <<
                    // value2 << "\n";
                }

                if (value1_bits != value2) {
                    getDebugStream() << hexval(flag.a1.phaddr) << "tag" << flag.tag << " value old  " << value1_bits
                                     << " new " << value2 << "\n";
                    set_reg_value(state, state_map, flag.a1, value2);
                    plgState->insert_reg_map(flag.a1.phaddr, state_map[flag.a1.phaddr]);
                    deal_rule_RWVB(state, flag.a1.phaddr, "V");
                }
            }
        }
    }
}

void NLPPeripheralModel::onExceptionExit(S2EExecutionState *state, uint32_t irq_no) {
    if (irq_no <= 15)
        return;
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    // interrupt vector+16
    // if (irq_no > 15)
    // plgState->set_exit_interrupt(irq_no - 16, false);
    if (irq_no > 15)
        irq_no -= 16;
    plgState->set_exit_interrupt(irq_no, -1);

    getInfoStream() << "EXIT Interrupt IRQ" << irq_no << " exit_inter = " << plgState->get_exit_interrupt(irq_no)
                    << "\n";
    // flip timer flag
    deal_rule_flag(state, 0);
}

void NLPPeripheralModel::onStatistics() {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, g_s2e_state);
    getInfoStream() << "write NLP statistics file\n";
    std::string NLPstafileName = s2e()->getOutputDirectory() + "/" + "NLPStatistics.dat";
    std::ofstream fPHNLP;

    fPHNLP.open(NLPstafileName, std::ios::out | std::ios::trunc);

    auto interrupt_freq = plgState->get_irqs_freq();
    for (auto interrupt : interrupt_freq) {
        fPHNLP << "interrupt id: " << interrupt.first << " freq: " << interrupt.second << "\n";
    }
    fPHNLP << "-------Verification Results-------\n";
    for (auto irq : unenabled_flag) {
        fPHNLP << "type one unenabled_flag: " << irq << "\n";
    }
    for (auto irq : untriggered_irq) {
        fPHNLP << "type two untriggered_irq: " << irq << "\n";
    }
    for (auto &phaddr : read_unauthorized_freq) {
        fPHNLP << "type three read unauthorized_freq: " << hexval(phaddr.first) << " corresponding SR: "
               << " at pc: ";
        for (auto pc : phaddr.second) {
            fPHNLP << " ; " << hexval(pc);
        }
        fPHNLP << "\n";
    }

    for (auto &phaddr : write_unauthorized_freq) {
        fPHNLP << "type four write unauthorized_freq: " << hexval(phaddr.first) << " corresponding SR: "
               << " at pc: ";
        for (auto pc : phaddr.second) {
            fPHNLP << " ; " << hexval(pc);
        }
        fPHNLP << "\n";
    }

    fPHNLP.close();
}

void NLPPeripheralModel::CheckEnable(S2EExecutionState *state, std::vector<uint32_t> &irq_no) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    std::map<uint32_t, uint32_t> interrupt_freq = plgState->get_irqs_freq();
    for (auto irq : irq_no) {
        getInfoStream() << "received irq: " << irq << "\n";
        if (interrupt_freq.find(irq) == interrupt_freq.end()) {
            unenabled_flag.insert(irq);
        }
    }
}

void NLPPeripheralModel::onEnableReceive(S2EExecutionState *state, uint32_t pc, uint64_t tb_num) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    //  Write a value to DR
    deal_rule_O(state);
    deal_rule_flag(state, 0);
    if (!plgState->check_instruction()) {
        hardware_write_to_receive_buffer(state);
    }
}

void NLPPeripheralModel::onUpdateBySignals(S2EExecutionState *state, SignalPair &irq_signals) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    RegMap state_map = plgState->get_state_map();
    for (auto &irq_signal : irq_signals) {
        if (find(irq_no.begin(), irq_no.end(), irq_signal.first) != irq_no.end()) {
            continue;
        }
        if (plgState->get_exit_interrupt(irq_signal.first))
            continue;
        getInfoStream() << "on Update By Signals: irq: " << irq_signal.first << "\n";

        for (auto &signal : irq_signal.second) {
            if (checkField(state, signal.control) && checkField(state, signal.dma) && checkField(state, signal.other)) {
                for (auto &key : signal.key) {
                    getInfoStream() << "key.type: " << key.type << " phaddr: " << key.phaddr << " bits: " << key.bits[0]
                                    << "\n";
                    if (key.type == "R") {
                        hardware_write_to_receive_buffer(state, key.phaddr);
                    } else if (key.type == "S") {
                        set_reg_value(state, state_map, key, key.value);
                        plgState->insert_reg_map(key.phaddr, state_map[key.phaddr]);
                        deal_rule_RWVB(state, key.phaddr, "V");
                    }
                }
            }
        }
    }
}

bool NLPPeripheralModel::checkField(S2EExecutionState *state, FieldList &fields) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    RegMap state_map = plgState->get_state_map();
    if (fields.size() == 0)
        return true;
    bool ans = true;
    for (auto &f : fields) {
        auto cur_value = state_map[f.phaddr].cur_value;
        uint32_t res = 0;
        for (int i = 0; i < f.bits.size(); ++i) {
            int tmp = f.bits[i];
            res = (res << 1) + (cur_value >> tmp & 1);
        }
        ans &= (res == f.value);
    }
    return ans;
}

void NLPPeripheralModel::onFirmwareFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                             const std::vector<klee::ref<klee::Expr>> &newConditions) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);
    RegMap state_map = plgState->get_state_map();
    ArrayVec results;
    findSymbolicObjects(newConditions[0], results);
    for (int i = results.size() - 1; i >= 0; --i) { // one cond multiple sym var
        uint32_t phaddr;
        uint32_t pc;
        uint32_t size;
        uint64_t no;
        auto &arr = results[i];

        getPeripheralExecutionState(arr->getName(), &phaddr, &pc, &size, &no);
        if (ExistInMMIO(phaddr)) {
            onFirmwareCondition.emit(state, phaddr, state_map[phaddr].cur_value);
        }
    }
}

bool NLPPeripheralModel::getPeripheralExecutionState(std::string variablePeripheralName, uint32_t *phaddr, uint32_t *pc,
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

void NLPPeripheralModel::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                               uint64_t pc) {
    signal->connect(sigc::bind(sigc::mem_fun(*this, &NLPPeripheralModel::onForkPoints), (unsigned) tb->se_tb_type));
}

void NLPPeripheralModel::onForkPoints(S2EExecutionState *state, uint64_t pc, unsigned source_type) {
    DECLARE_PLUGINSTATE(NLPPeripheralModelState, state);

    if (pc == fork_point) {
        getInfoStream() << "at fork_point:" << hexval(fork_point) << "\n";
        init_dr_flag = true;
        plgState->inc_fork_count();
        if (plgState->get_fork_point_count() < 2) {
            return;
        }

        deal_rule_O(state);
        deal_rule_flag(state, 0);
        if (plgState->pending_interrupt()) {
            return;
        }
        CheckEnable(state, irq_no);
        getWarningsStream() << "already go though Main Loop Point Count = " << plgState->get_fork_point_count() << "\n";
        getWarningsStream() << "===========unit test pass============\n";
        g_s2e->getCorePlugin()->onEngineShutdown.emit();
        // Flush here just in case ~S2E() is not called (e.g., if atexit()
        // shutdown handler was not called properly).
        g_s2e->flushOutputStreams();
        exit(0);
    }
}

void NLPPeripheralModel::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc, bool staticTarget, uint64_t staticTargetPc) {
    signal->connect(sigc::mem_fun(*this, &NLPPeripheralModel::onFeedData));
}

void NLPPeripheralModel::onFeedData(S2EExecutionState *state, uint64_t cur_loc) {
    getInfoStream(state) << state->regs()->getInterruptFlag() << " current pc = " << hexval(cur_loc) << " re tb num "
                         << "\n";
    if (init_dr_flag == true && (!state->regs()->getInterruptFlag())) {
        deal_rule_O(state);
        deal_rule_flag(state, 0);
        hardware_write_to_receive_buffer(state);
        init_dr_flag = false;
    }
}


} // namespace plugins
} // namespace s2e
