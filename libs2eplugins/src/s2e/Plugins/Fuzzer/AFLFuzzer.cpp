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


static void afl_setup(void) {
/* Set up SHM region and initialize other stuff. */
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

    for (int i = 0; i < rom_num; ++i) {
        std::stringstream ssrom;
        ssrom << "mem.rom"
              << "[" << (i + 1) << "]";
        MEM rom;
        rom.baseaddr = cfg->getInt(ssrom.str() + "[1]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse " << ssrom.str() + "baseaddr"
                                << "\n";
            exit(-1);
        }
        rom.size = cfg->getInt(ssrom.str() + "[2]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse " << ssrom.str() + "size"
                                << "\n";
            exit(-1);
        }
        roms.push_back(rom);
        getDebugStream() << "valid rom " << i + 1 << " baseaddr:" << hexval(roms[i].baseaddr)
                         << " size:" << hexval(roms[i].size) << "\n";
    }

    for (int i = 0; i < ram_num; ++i) {
        std::stringstream ssram;
        ssram << "mem.ram"
              << "[" << (i + 1) << "]";
        MEM ram;
        ram.baseaddr = cfg->getInt(ssram.str() + "[1]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse " << ssram.str() + "baseaddr"
                                << "\n";
            exit(-1);
        }
        ram.size = cfg->getInt(ssram.str() + "[2]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse " << ssram.str() + "size"
                                << "\n";
            exit(-1);
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
    max_afl_size = s2e()->getConfig()->getInt(getConfigKey() + ".maxTCSize", 128, &ok);
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
    systick_flag = 0;
    hit_flag = false;

    // crash or hang analysis
    tc_length = 0;
    std::string testcaseName = s2e()->getConfig()->getString(getConfigKey() + ".testcaseName", "NULL", &ok);
    if (ok) {
        std::ifstream fT;
        fT.open(testcaseName, std::ios::in | std::ios::binary);
        if (!fT) {
            getWarningsStream() << "No Testcase file Provided\n";
        }

        char tcB;
        while (fT.read(&tcB, sizeof(tcB))) {
            memcpy(testcase + tc_length, &tcB, 1);
            getInfoStream() << "input testcase " << hexval(tcB) << "\n";
            tc_length += fT.gcount();
        }
        fT.close();
        if (tc_length <= 0) {
            getWarningsStream() << " The length of testcase should greater than zero\n";
            exit(-1);
        }
    }
}

void AFLFuzzer::forkPoint(S2EExecutionState *state) {

    state->jumpToSymbolicCpp();


    std::string name = "fork_point";

   // add a meaningless symbol for a cond to fork
    klee::ref<klee::Expr> var = state->createSymbolicValue<uint32_t>(name, 0);

    for (unsigned i = 1; i < 2; ++i) {
        klee::ref<klee::Expr> val = klee::ConstantExpr::create(i, var->getWidth());
        klee::ref<klee::Expr> cond = klee::NeExpr::create(var, val);

        klee::Executor::StatePair sp = s2e()->getExecutor()->forkCondition(state, cond, true);
        assert(sp.first == state);
        assert(sp.second && sp.second != sp.first);
        if (sp.second) {
            // Re-execute the plugin invocation in the other state
            sp.second->pc = sp.second->prevPC;
        }
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
    return false;
}

static void PrintRegs(S2EExecutionState *state) {
    for (unsigned i = 0; i < 16; ++i) {
        unsigned offset = offsetof(CPUARMState, regs[i]);
        target_ulong concreteData;

        getConcolicValue(state, offset, &concreteData);
        g_s2e->getInfoStream() << "Regs " << i << " = " << hexval(concreteData) << "\n";
    }
}

void AFLFuzzer::restoreSymRegs(S2EExecutionState *state) {
    for (unsigned i = 0; i < 16; ++i) {
        bool ret = state->regs()->write<target_ulong>(CPU_OFFSET(regs[i]), reg_snapshot[i]);
        assert(ret);
    }
}

void AFLFuzzer::saveSymRegs(S2EExecutionState *state) {
    reg_snapshot.clear();
    if (reg_snapshot.size() == 0) {
        for (unsigned i = 0; i < 16; ++i) {
            unsigned offset = offsetof(CPUARMState, regs[i]);
            target_ulong concreteData;
            getConcolicValue(state, offset, &concreteData);
            reg_snapshot.push_back(concreteData);
            g_s2e->getInfoStream() << "Regs " << i << " = " << hexval(reg_snapshot[i]) << "\n";
        }
    } else {
        return;
    }
}

void AFLFuzzer::onCrashHang(S2EExecutionState *state, uint32_t flag) {
    PrintRegs(state);
    systick_flag = 0;
    memcpy(afl_area_ptr, bitmap, MAP_SIZE);
    if (flag != 0) {
        afl_con->AFL_return = FAULT_CRASH;
    } else {
        afl_con->AFL_return = FAULT_TMOUT;
    }
    invaild_pc = 0;
    for (auto phaddr_cur_loc : cur_read) {
        cur_read[phaddr_cur_loc.first] = 0;
    }
    Ethernet.pos = 0;
    if (tc_length == 0) { // Fuzzing
        restoreMemRegSnapShot(state);
        restoreSymRegs(state);
        PrintRegs(state);
        s2e()->getExecutor()->doDeviceStateRestore(state);
    } else {
        g_s2e->getCorePlugin()->onEngineShutdown.emit();
        // Flush here just in case ~S2E() is not called (e.g., if atexit()
        // shutdown handler was not called properly).
        g_s2e->flushOutputStreams();
        exit(0);
    }
}

void AFLFuzzer::onTimer() {
    ++timer_ticks;
}

void AFLFuzzer::onModeSwitch(S2EExecutionState *state, bool fuzzing_to_learning, bool *fork_point_flag) {
    if (fuzzing_to_learning) {
        if (hit_flag) {
            memcpy(afl_area_ptr, bitmap, MAP_SIZE);
            afl_con->AFL_input = 0;
        } else {
            *fork_point_flag = false;
        }
        concreteDataMemoryAccessConnection.disconnect();
        invalidPCAccessConnection.disconnect();
        timerConnection.disconnect();
        timer_ticks = 0;
    } else {
        getInfoStream() << " AFL Reconnection !!\n";
        if (hit_flag) {
            hit_flag = false;
        } else {
            *fork_point_flag = false;
        }
        timer_ticks = 0;
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
    onCrashHang(state, INVALIDPH);
}

void AFLFuzzer::onFuzzingInput(S2EExecutionState *state, PeripheralRegisterType type, uint32_t phaddr,
                               uint32_t t3_count, uint32_t *size, uint32_t *value, bool *doFuzz) {

    memset(value, 0, 4 * sizeof(char));
    for (auto input_peripheral : input_peripherals) {
        if (input_peripheral.first == phaddr) {
            *doFuzz = true;
            *size = input_peripherals[phaddr];
            break;
        } else if (input_peripherals.size() > 0){
            *doFuzz = false;
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
        if (hit_flag == false) {
            afl_con->AFL_return = 0;
            invaild_pc = 0;
            cur_read.clear();
            Ethernet.pos = 0;
            getInfoStream() << "fork point phaddr  = " << hexval(phaddr)
                                << " pc = " << hexval(state->regs()->getPc()) << "\n";
            forkPoint(state);
            saveMemRegSnapShot(state);
            saveSymRegs(state);
            s2e()->getExecutor()->doDeviceStateSave(state);
        }

        hit_flag = true;
        timer_ticks = 0;
        uint32_t afl_length;
        if (tc_length == 0) { // Fuzzing
            if (afl_con->AFL_size > max_afl_size) {
               afl_length = max_afl_size;
                getDebugStream() << " max_size = " << max_afl_size << "\n";
            } else {
                afl_length = afl_con->AFL_size;
            }
            if (cur_read[phaddr] >= afl_length) { // fork point
                if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() == 15 && systick_flag != 2) {
                    cur_read[phaddr] = 0;
                    systick_flag = 1;
                } else {
                    for (auto phaddr_cur_loc : cur_read) {
                        cur_read[phaddr_cur_loc.first] = 0;
                    }
                    getDebugStream() <<  " phaddr first = " << hexval(phaddr) << " phaddr second" << hexval(cur_read[phaddr]) << "\n";
                    memcpy(afl_area_ptr, bitmap, MAP_SIZE);
                    afl_con->AFL_input = 0;
                    systick_flag = 0;
                    getDebugStream() << "testcase finish "<< " pc = " << hexval(state->regs()->getPc()) << "\n";
                    restoreMemRegSnapShot(state);
                    restoreSymRegs(state);
                    s2e()->getExecutor()->doDeviceStateRestore(state);
                    return;
                }
            }

            if (afl_con->AFL_input) {
                getDebugStream() << "AFL_input = " << afl_con->AFL_input << " AFL_size = " << afl_con->AFL_size
                                 << " cur_read = " << cur_read[phaddr] << "\n";
                memcpy(value, testcase + cur_read[phaddr], *size);
                cur_read[phaddr] += *size;
            } else {
                memset(value, 0, 4 * sizeof(char));
                cur_read[phaddr] = 0;
            }
        } else {
            if (cur_read[phaddr] >= tc_length) {
                getInfoStream() << "The whole testcase has been read by firmware, specific testcase analysis finish\n";
                g_s2e->getCorePlugin()->onEngineShutdown.emit();
                // Flush here just in case ~S2E() is not called (e.g., if atexit()
                // shutdown handler was not called properly).
                g_s2e->flushOutputStreams();
                exit(0);
            }
            memcpy(value, testcase + cur_read[phaddr], *size);
            cur_read[phaddr] += *size;
            getInfoStream() << " read the " << cur_read[phaddr] << " Bytes from whole testcase :" << hexval(*value) << "\n";
        }
    }
}

void AFLFuzzer::saveMemRegSnapShot(S2EExecutionState *state) {
    // ram regions
    mems_snapshot.clear();
    if (mems_snapshot.size() == 0) {
        for (uint32_t j = 0; j < rams.size(); j++) {
            std::vector<uint32_t> mem_snapshot;
            for (uint32_t i = 0; i < rams[j].size; i = i+4) {
                uint32_t ram_data = 0;
                bool ok = state->mem()->read(rams[j].baseaddr + i, &ram_data, sizeof(ram_data));
                mem_snapshot.push_back(ram_data);
                if (ok) {
                   // getDebugStream(state) << "read mem addr:" << hexval(rams[j].baseaddr+i) << " value = " << hexval(ram_data) << "\n";
                } else {
                    getWarningsStream(state) << "read mem addr:" << hexval(rams[j].baseaddr+i) << "fail!!\n";
                    exit(-1);
                }
            }
            mems_snapshot.push_back(mem_snapshot);
        }
    }
}

void AFLFuzzer::restoreMemRegSnapShot(S2EExecutionState *state) {
    // ram regions
    for (uint32_t j = 0; j < rams.size(); j++) {
        for (uint32_t i = 0; i < rams[j].size; i = i+4) {
            bool ok = state->mem()->write(rams[j].baseaddr + i, &mems_snapshot[j][i/4], sizeof(mems_snapshot[j][i/4]));
            if (ok) {
                getDebugStream(state) << "write mem addr:" << hexval(rams[j].baseaddr+i) << " value = " << hexval(mems_snapshot[j][i/4]) << "\n";
            } else {
                getWarningsStream(state) << "write mem addr:" << hexval(rams[j].baseaddr+i) << "fail!!\n";
                exit(-1);
            }
        }
    }
}

void AFLFuzzer::onInvalidPCAccess(S2EExecutionState *state, uint64_t addr) {
    uint32_t pc = state->regs()->getPc();
    getWarningsStream() << "Kill path due to invaild pc  = " << hexval(pc) << " addr = " << hexval(addr) << "\n";
    onCrashHang(state, INVALIDPC);
}

void AFLFuzzer::onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address, uint64_t value, uint8_t size,
                                           unsigned flags) {

    if (!hit_flag) {
        return;
    }

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
        onCrashHang(state, OBREAD);
    } else {
        if (address > rams[0].baseaddr + rams[0].size) {
            getWarningsStream() << "Kill Fuzz State due to out of bound write, access address = " << hexval(address)
                                << " pc = " << hexval(pc) << "\n";
            onCrashHang(state, OBWRITE);
        } else if (address > roms[0].baseaddr + 0x100 && address < (roms[0].baseaddr + roms[0].size)){
            getWarningsStream() << "Kill Fuzz State due to writing read-only rom address = " << hexval(address)
                                << " pc = " << hexval(pc) << "\n";
            onCrashHang(state, OBWRITE);
        } else {
            return;
        }
    }

}

void AFLFuzzer::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t pc, bool staticTarget,
                                                 uint64_t staticTargetPc) {
    signal->connect(
        sigc::bind(sigc::mem_fun(*this, &AFLFuzzer::onBlockEnd), (unsigned) tb->se_tb_type));
}

void AFLFuzzer::onBlockEnd(S2EExecutionState *state, uint64_t cur_loc, unsigned source_type) {
    static __thread uint64_t prev_loc;

    if (!g_s2e_cache_mode) {
        return;
    }
    // uEmu ends up with fuzzer
    if (unlikely(afl_con->AFL_return == END_uEmu)) {
        getInfoStream() << "==== Testing aborted by user via Fuzzer ====\n";
        g_s2e->getCorePlugin()->onEngineShutdown.emit();
        // Flush here just in case ~S2E() is not called (e.g., if atexit()
        // shutdown handler was not called properly).
        g_s2e->flushOutputStreams();
        exit(0);
    }

    if (timer_ticks > (hang_timeout - 1)) {
        getWarningsStream() << state->regs()->getInterruptFlag() << g_s2e_allow_interrupt << g_s2e_fast_concrete_invocation << " what happen when we are hang at pc = "
                            << hexval(cur_loc) << ", maybe add it as a crash point\n";
    }

    if (!state->regs()->getInterruptFlag() && systick_flag == 1) {
        systick_flag = 2;
    }

    // user-defined crash points
    for (auto crash_point : crash_points) {
        if (crash_point == cur_loc) {
            getWarningsStream() << "Kill Fuzz state due to user-defined crash points\n";
            onCrashHang(state, UDPC);
        }
    }

    // path bitmap
    if (cur_loc > afl_end_code || cur_loc < afl_start_code || !bitmap)
        return;

    /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

    // Do not map external interrupt
    if (state->regs()->getInterruptFlag()) {
        if (state->regs()->getExceptionIndex() > 15) {
            return;
        } else if (state->regs()->getExceptionIndex() == 15) {
            cur_loc = (cur_loc >> 8) ^ (cur_loc << 4);
            cur_loc &= MAP_SIZE - 1;
            cur_loc |= 0x8000;
            if (cur_loc >= afl_inst_rms)
                return;
            if (bitmap[cur_loc]) // only count once for systick irq
                return;
            bitmap[cur_loc]++;
            return;
        }
    }

    cur_loc = (cur_loc >> 8) ^ (cur_loc << 4);
    cur_loc &= MAP_SIZE/2 - 1;

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
        onCrashHang(state, TMOUT);
    }

    if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() < 10) {
        getWarningsStream() << "Kill Fuzz State due to Fault interrupt = " << state->regs()->getExceptionIndex()
                            << " pc = " << hexval(state->regs()->getPc()) << "\n";
        onCrashHang(state, HARDFAULT);
    }
}

} // namespace plugins
} // namespace s2e
