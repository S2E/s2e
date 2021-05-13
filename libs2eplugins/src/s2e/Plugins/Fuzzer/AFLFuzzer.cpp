///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <sys/shm.h>

#include "AFLFuzzer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(AFLFuzzer, "trigger and record external interrupts", "AFLFuzzer", "PeripheralModelLearning");

class AFLFuzzerState : public PluginState {
private:
    typedef llvm::DenseMap<uint32_t, uint32_t> TBCounts;

    uint64_t hit_count;

public:
    AFLFuzzerState() {
        hit_count = 0;
    }

    virtual ~AFLFuzzerState() {
    }

    static PluginState *factory(Plugin *, S2EExecutionState *) {
        return new AFLFuzzerState();
    }

    AFLFuzzerState *clone() const {
        return new AFLFuzzerState(*this);
    }

    void inc_hit_count() {
        hit_count++;
    }

    uint64_t get_hit_count() {
        return hit_count;
    }

    void clear_hit_count() {
        hit_count = 0;
    }
};

/* Set up SHM region and initialize other stuff. */

static void afl_setup(void) {

    AFL_shm_id = shmget((key_t) AFL_IoT_S2E_KEY, sizeof(struct AFL_data), IPC_CREAT | 0660);
    bitmap_shm_id = shmget((key_t) AFL_BITMAP_KEY, MAP_SIZE, IPC_CREAT | 0660);
    testcase_shm_id = shmget((key_t) AFL_TESTCASE_KEY, TESTCASE_SIZE, IPC_CREAT | 0660);

    if (AFL_shm_id < 0 || bitmap_shm_id < 0) {
        printf("shmget error\n");
        exit(-1);
    } else {
        printf("AFL_shm_id = %d bitmap_shm_id = %d\n", AFL_shm_id, bitmap_shm_id);
    }

    afl_shm = shmat(AFL_shm_id, NULL, 0);
    bitmap_shm = shmat(bitmap_shm_id, NULL, 0);
    testcase_shm = shmat(testcase_shm_id, NULL, 0);
    afl_con = (struct AFL_data *) afl_shm;
    afl_area_ptr = (unsigned char *) bitmap_shm;
    testcase = (uint8_t *) testcase_shm;
    if (!afl_area_ptr || !afl_con) {
        printf("shmat error\n");
        exit(-1);
    }
}

void AFLFuzzer::initialize() {

    bool ok;
    ConfigFile *cfg = s2e()->getConfig();

    enable_fuzzing = s2e()->getConfig()->getBool(getConfigKey() + ".useAFLFuzzer", false);
    if (!enable_fuzzing) {
        getWarningsStream()
            << "Please ensure 'enable_fuzz' is true in your .cfg file! AFLFuzzer can be only used in cache mode\n";
        return;
    }

    int input_peripheral_size = g_s2e->getConfig()->getListSize(getConfigKey() + ".inputPeripherals", &ok);

    for (unsigned i = 0; i < input_peripheral_size; i++) {
        uint32_t phaddr, size;
        std::stringstream ssphs;
        ssphs << getConfigKey() << ".inputPeripherals"
              << "[" << (i + 1) << "]";

        phaddr = cfg->getInt(ssphs.str() + "[1]", 0, &ok);
        size = cfg->getInt(ssphs.str() + "[2]", 0, &ok);
        if (size > 4) {
            Ethernet.addr = phaddr;
            Ethernet.size = size;
            Ethernet.pos = 0;
        } else {
            input_peripherals[phaddr] = size;
        }

        getDebugStream() << "Add fuzzing target ph address = " << hexval(phaddr) << " size = " << hexval(size) << "\n";
    }

    if (!ok) {
        getWarningsStream() << " input peripherals is not vaild\n";
        exit(-1);
    }

    int additional_range_size = g_s2e->getConfig()->getListSize(getConfigKey() + ".writeRanges", &ok);
    for (unsigned i = 0; i < additional_range_size; i++) {
        uint32_t baseaddr, size;
        std::stringstream ssranges;
        ssranges << getConfigKey() << ".writeRanges"
                 << "[" << (i + 1) << "]";

        baseaddr = cfg->getInt(ssranges.str() + "[1]", 0, &ok);
        size = cfg->getInt(ssranges.str() + "[2]", 0, &ok);
        additional_writeable_ranges[baseaddr] = size;

        getDebugStream() << "Add additional writeable address = " << hexval(baseaddr) << " size = " << hexval(size)
                         << "\n";
    }

    int rom_num = g_s2e->getConfig()->getListSize("mem.rom");
    int ram_num = g_s2e->getConfig()->getListSize("mem.ram");
    std::stringstream ssrom;
    std::stringstream ssram;

    for (int i = 0; i < rom_num; ++i) {
        ssrom << "mem.rom"
              << "[" << (i + 1) << "]";
        MEM rom;
        rom.baseaddr = cfg->getInt(ssrom.str() + "[1]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse " << ssrom.str() + "baseaddr"
                                << "\n";
            return;
        }
        rom.size = cfg->getInt(ssrom.str() + "[2]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse " << ssrom.str() + "size"
                                << "\n";
            return;
        }
        roms.push_back(rom);
        getDebugStream() << "valid rom " << i + 1 << " baseaddr:" << hexval(roms[i].baseaddr)
                         << " size:" << hexval(roms[i].size) << "\n";
    }

    for (int i = 0; i < ram_num; ++i) {
        ssram << "mem.ram"
              << "[" << (i + 1) << "]";
        MEM ram;
        ram.baseaddr = cfg->getInt(ssram.str() + "[1]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse " << ssram.str() + "baseaddr"
                                << "\n";
            return;
        }
        ram.size = cfg->getInt(ssram.str() + "[2]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse " << ssram.str() + "size"
                                << "\n";
            return;
        }
        rams.push_back(ram);
        getDebugStream() << "valid ram " << i + 1 << " baseaddr:" << hexval(rams[i].baseaddr)
                         << " size:" << hexval(rams[i].size) << "\n";
    }

    blockEndConnection = s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
        sigc::mem_fun(*this, &AFLFuzzer::onTranslateBlockEnd));
    concreteDataMemoryAccessConnection = s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(
        sigc::mem_fun(*this, &AFLFuzzer::onConcreteDataMemoryAccess));

    invalidPCAccessConnection =
        s2e()->getCorePlugin()->onInvalidPCAccess.connect(sigc::mem_fun(*this, &AFLFuzzer::onInvalidPCAccess));
    timer_ticks = 0;
    timerConnection = s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &AFLFuzzer::onTimer));
    hang_timeout = s2e()->getConfig()->getInt(getConfigKey() + ".hangTimeout", 10);
    max_fork_count = s2e()->getConfig()->getInt(getConfigKey() + ".forkCount", 10, &ok);
    if (max_fork_count < 100) {
        getWarningsStream()
            << "Too frequent fork will slow down fuzzing speed and very like go to the deep path!!!\n";
    }

    auto crash_keys = cfg->getIntegerList(getConfigKey() + ".crashPoints");
    foreach2 (it, crash_keys.begin(), crash_keys.end()) {
        getWarningsStream() << "Add kill point address = " << hexval(*it) << "\n";
        crash_points.push_back(*it);
    }

    hw::PeripheralModelLearning *PeripheralConnection = s2e()->getPlugin<hw::PeripheralModelLearning>();
    PeripheralConnection->onFuzzingInput.connect(sigc::mem_fun(*this, &AFLFuzzer::onFuzzingInput));
    PeripheralConnection->onModeSwitch.connect(sigc::mem_fun(*this, &AFLFuzzer::onModeSwitch));
    PeripheralConnection->onInvalidPHs.connect(sigc::mem_fun(*this, &AFLFuzzer::onInvalidPHs));

    afl_setup();

    bitmap = (uint8_t *) malloc(MAP_SIZE);
    afl_start_code = 0;
    afl_end_code = 0xffffffff;
    cur_read = 0;
    unique_tb_num = 0;
}

static void SymbHwGetConcolicVector(uint64_t in, unsigned size, hw::ConcreteArray &out) {
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

static void PrintRegs(S2EExecutionState *state) {
    for (unsigned i = 0; i < 15; ++i) {
        unsigned offset = offsetof(CPUARMState, regs[i]);
        target_ulong concreteData;

        getConcolicValue(state, offset, &concreteData);
        g_s2e->getInfoStream() << "Regs " << i << " = " << hexval(concreteData) << "\n";
    }
}

void AFLFuzzer::onCrashHang(S2EExecutionState *state, uint32_t flag) {
    PrintRegs(state);
    memcpy(afl_area_ptr, bitmap, MAP_SIZE);
    if (flag == 1) {
        afl_con->AFL_return = FAULT_CRASH;
    } else {
        afl_con->AFL_return = FAULT_TMOUT;
    }
    std::string s;
    llvm::raw_string_ostream ss(s);
    ss << "Kill path due to Crash/Hang\n";
    ss.flush();
    s2e()->getExecutor()->terminateState(*state, s);
}

void AFLFuzzer::onTimer() {
    ++timer_ticks;
}

void AFLFuzzer::onModeSwitch(S2EExecutionState *state, bool fuzzing_to_learning) {
    DECLARE_PLUGINSTATE(AFLFuzzerState, state);
    if (fuzzing_to_learning) {
        memcpy(afl_area_ptr, bitmap, MAP_SIZE);
        afl_con->AFL_input = 0;
        // afl_con->AFL_return = FAULT_ERROR;
        blockEndConnection.disconnect();
        concreteDataMemoryAccessConnection.disconnect();
        invalidPCAccessConnection.disconnect();
        timerConnection.disconnect();
        plgState->clear_hit_count();
        timer_ticks = 0;
    } else {
        getInfoStream() << " AFL Reconnection !!\n";
        timer_ticks = 0;
        blockEndConnection = s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &AFLFuzzer::onTranslateBlockEnd));
        concreteDataMemoryAccessConnection = s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(
            sigc::mem_fun(*this, &AFLFuzzer::onConcreteDataMemoryAccess));
        invalidPCAccessConnection =
            s2e()->getCorePlugin()->onInvalidPCAccess.connect(sigc::mem_fun(*this, &AFLFuzzer::onInvalidPCAccess));
        timerConnection = s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &AFLFuzzer::onTimer));
    }
}

void AFLFuzzer::onInvalidPHs(S2EExecutionState *state, uint64_t addr) {
    getWarningsStream() << "Kill path due to onInvalid PHs at pc = " << hexval(state->regs()->getPc())
                        << "ph addr = " << hexval(addr) << "\n";
    onCrashHang(state, 1);
}

void AFLFuzzer::onFuzzingInput(S2EExecutionState *state, PeripheralRegisterType type, uint64_t phaddr,
                               uint32_t t3_count, uint32_t *size, uint32_t *value, bool *doFuzz) {
    DECLARE_PLUGINSTATE(AFLFuzzerState, state);

    memset(value, 0, 4 * sizeof(char));
    for (auto input_peripheral : input_peripherals) {
        if (input_peripheral.first == phaddr) {
            *doFuzz = true;
            *size = input_peripherals[phaddr];
            break;
        }
    }

    if (phaddr >= Ethernet.addr && phaddr < Ethernet.addr + Ethernet.size) {
        *doFuzz = true;
        *size = 1;
        Ethernet.pos++;
        if (Ethernet.pos == Ethernet.size) {
            Ethernet.pos = 0;
        }
    }

    if (*doFuzz && g_s2e_cache_mode && t3_count == 0) {
        if (plgState->get_hit_count() == 0) {
            afl_con->AFL_return = 0;
            invaild_pc = 0;
            cur_read = 0;
            Ethernet.pos = 0;
            getDebugStream() << "fork at checking point phaddr  = " << hexval(phaddr)
                                << " pc = " << hexval(state->regs()->getPc()) << "\n";
            hw::ConcreteArray concolicValue;
            SymbHwGetConcolicVector(0x0, *size, concolicValue);
            klee::ref<klee::Expr> original_value =
                state->createSymbolicValue("checking_point", *size * 8, concolicValue);
            s2e()->getExecutor()->forkAndConcretize(state, original_value);
        }

        plgState->inc_hit_count();
        timer_ticks = 0;

        if (cur_read >= afl_con->AFL_size) {
            cur_read = 0;
            memcpy(afl_area_ptr, bitmap, MAP_SIZE);
            afl_con->AFL_input = 0;
            fork_count++;
            if (fork_count > max_fork_count) {
                fork_count = 0;
                std::string s;
                llvm::raw_string_ostream ss(s);
                ss << "Fork point each " << max_fork_count << " testcases\n";
                ss.flush();
                s2e()->getExecutor()->terminateState(*state, s);
            }
        }

        if (afl_con->AFL_input) {
            getDebugStream() << "AFL_input = " << afl_con->AFL_input << " AFL_size = " << afl_con->AFL_size
                             << " cur_read = " << cur_read << "\n";
            memcpy(value, testcase + cur_read, *size);
            cur_read += *size;
        } else {
            memset(value, 0, 4 * sizeof(char));
            cur_read = 0;
        }
    }
}

void AFLFuzzer::onInvalidPCAccess(S2EExecutionState *state, uint64_t addr) {
    uint32_t pc = state->regs()->getPc();
    getWarningsStream() << "Kill path due to invaild pc  = " << hexval(pc) << " addr = " << hexval(addr) << "\n";
    onCrashHang(state, 1);
}

void AFLFuzzer::onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address, uint64_t value, uint8_t size,
                                           unsigned flags) {

    bool is_write = false;
    if (flags & MEM_TRACE_FLAG_WRITE) {
        is_write = true;
    }
    uint32_t pc = state->regs()->getPc();

    // ram regions
    for (auto ram : rams) {
        if (address >= ram.baseaddr && address <= (ram.baseaddr + ram.size)) {
            return;
        }
    }

    // peripheral regions
    if (address >= 0x40000000 && address < 0x60000000) {
        return;
    }

    // external peripheral regions
    if (address >= 0xe0000000 && address < 0xe0100000) {
        return;
    }

    // additional user-defined available rw regions
    for (auto writeable_range : additional_writeable_ranges) {
        if (address >= writeable_range.first && address < writeable_range.first + writeable_range.second) {
            return;
        }
    }

    if (!is_write) {
        // only allow read from rom regions
        for (auto rom : roms) {
            if (address >= rom.baseaddr && address < (rom.baseaddr + rom.size)) {
                return;
            }
        }
        getWarningsStream() << "Kill Fuzz State due to out of bound read, access address = " << hexval(address)
                            << " pc = " << hexval(pc) << "\n";
    } else {
        getWarningsStream() << "Kill Fuzz State due to out of bound write, access address = " << hexval(address)
                            << " pc = " << hexval(pc) << "\n";
    }

    onCrashHang(state, 1);
}

void AFLFuzzer::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t pc, bool staticTarget,
                                                 uint64_t staticTargetPc) {
    signal->connect(
        sigc::bind(sigc::mem_fun(*this, &AFLFuzzer::onBlockEnd), (unsigned) tb->se_tb_type));
}

void AFLFuzzer::onBlockEnd(S2EExecutionState *state, uint64_t cur_loc, unsigned source_type) {
    static __thread uint64_t prev_loc;

    // record total bb number
    if (all_tb_map[cur_loc] < 1) {
        ++unique_tb_num;
        ++all_tb_map[cur_loc];
    }

    // uEmu ends up with fuzzer
    if (unlikely(afl_con->AFL_return == END_uEmu)) {
        getInfoStream() << "The total number of unqiue executed bb is " << unique_tb_num << "\n";
        getInfoStream() << "==== Testing aborted by user via Fuzzer ====\n";
        g_s2e->getCorePlugin()->onEngineShutdown.emit();
        // Flush here just in case ~S2E() is not called (e.g., if atexit()
        // shutdown handler was not called properly).
        g_s2e->flushOutputStreams();
        exit(0);
    }

    if (timer_ticks > (hang_timeout - 1)) {
        getWarningsStream() << g_s2e_allow_interrupt << " what happen when we are hang at pc = "
                            << hexval(cur_loc) << ", maybe add it as a crash point\n";
    }

    // user-defined crash points
    for (auto crash_point : crash_points) {
        if (crash_point == cur_loc) {
            getWarningsStream() << "Kill Fuzz state due to user-defined crash points\n";
            onCrashHang(state, 1);
        }
    }

    // path bitmap
    if (cur_loc > afl_end_code || cur_loc < afl_start_code || !bitmap)
        return;

    /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 1;

    /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

    if (cur_loc >= afl_inst_rms)
        return;
    bitmap[cur_loc ^ prev_loc]++;
    prev_loc = cur_loc >> 1;

    // getDebugStream() << "count bitmap = " << count_bytes(bitmap) << "\n";

    // crash/hang
    if (timer_ticks > hang_timeout) {
        timer_ticks = 0;
        getWarningsStream() << "Kill Fuzz State due to Timeout\n";
        onCrashHang(state, 0);
    }

    if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() < 10) {
        getWarningsStream() << "Kill Fuzz State due to Fault interrupt = " << state->regs()->getExceptionIndex()
                            << " pc = " << hexval(state->regs()->getPc()) << "\n";
        onCrashHang(state, 1);
    }
}

} // namespace plugins
} // namespace s2e
