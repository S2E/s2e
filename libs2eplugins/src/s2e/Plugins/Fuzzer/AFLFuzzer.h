///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_EXAMPLE_H
#define S2E_PLUGINS_EXAMPLE_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/uEmu/PeripheralModelLearning.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/SymbolicHardwareHook.h>

namespace s2e {
namespace plugins {
typedef llvm::DenseMap<uint32_t, uint32_t> TBCounts;

/* Map size for the traced binary (2^MAP_SIZE_POW2). Must be greater than
   2; you probably want to keep it under 18 or so for performance reasons
   (adjusting AFL_INST_RATIO when compiling is probably a better way to solve
   problems with complex programs). You need to recompile the target binary
   after changing this - otherwise, SEGVs may ensue. */

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)
/* Environment variable used to pass SHM ID to the called program. */
#define SHM_ENV_VAR "__AFL_SHM_ID"
static unsigned int afl_inst_rms = MAP_SIZE;
static unsigned char *afl_area_ptr;
static uint8_t *testcase;
static uint8_t *bitmap;
struct AFL_data *afl_con;
static int32_t AFL_shm_id, bitmap_shm_id, testcase_shm_id;
#define AFL_IoT_S2E_KEY 7777
#define AFL_BITMAP_KEY 8888
#define AFL_TESTCASE_KEY 9999
#define TESTCASE_SIZE 2048
void *afl_shm = NULL;
void *bitmap_shm = NULL;
void *testcase_shm = NULL;
struct AFL_data {
    uint8_t AFL_round;
    uint8_t AFL_input;
    uint8_t AFL_return;
    uint32_t AFL_size;
};
/* Execution status fault codes */
enum {
    /* 00 */ FAULT_NONE,
    /* 01 */ FAULT_TMOUT,
    /* 02 */ FAULT_CRASH,
    /* 03 */ FAULT_ERROR,
    /* 04 */ FAULT_NOINST,
    /* 05 */ FAULT_NOBITS,
    /* 06 */ END_uEmu
};
class AFLFuzzer : public Plugin {
    S2E_PLUGIN
public:
    AFLFuzzer(S2E *s2e) : Plugin(s2e) {
    }

    sigc::signal<void, S2EExecutionState *, uint32_t /* Fuzzer End Tyep */> onFuzzerTerminationEvent;

    void initialize();

    struct MEM {
        uint32_t baseaddr;
        uint32_t size;
    };

    typedef struct TESTCASE {
        uint32_t remain_read;
        char testcase[1024];
    } PHTS;

    typedef struct input_buffer {
        uint32_t addr;
        uint32_t size;
        uint32_t pos;
    } Fuzz_Buffer;

private:
    sigc::connection concreteDataMemoryAccessConnection;
    sigc::connection invalidPCAccessConnection;
    sigc::connection blockEndConnection;
    sigc::connection timerConnection;
    TBCounts all_tb_map;
    uint64_t unique_tb_num; // new tb number
    bool enable_fuzzing;
    uint32_t max_fork_count;
    uint32_t fork_count;
    std::map<uint32_t /* phaddr */, uint32_t /* size */> input_peripherals;
    std::map<uint32_t /* phaddr */, uint32_t /* size */> additional_writeable_ranges;
    Fuzz_Buffer Ethernet;
    // std::map<uint32_t /* phaddr */, PHTS /* testcase */> phstestcases;
    uint32_t cur_read;
    std::vector<uint32_t> crash_points;
    uint32_t invaild_pc;
    std::vector<MEM> roms;
    std::vector<MEM> rams;
    uint64_t afl_start_code; /* .text start pointer      */
    uint64_t afl_end_code;   /* .text end pointer        */
    uint64_t hang_timeout;
    uint64_t timer_ticks;
    std::map<uint32_t /* phaddr */, uint32_t /* testcase_loc */> ph_tc_loc;
    std::map<uint32_t /* phaddr */, uint32_t /* last value */> ph_last_value;
    void onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t vaddr, uint64_t value, uint8_t size,
                                    unsigned flags);
    void onInvalidPHs(S2EExecutionState *state, uint64_t addr);
    void onModeSwitch(S2EExecutionState *state, bool fuzzing_to_learning);
    void onInvalidPCAccess(S2EExecutionState *state, uint64_t addr);
    void onFuzzingInput(S2EExecutionState *state, PeripheralRegisterType type, uint64_t phaddr, uint32_t t3_count,
                        uint32_t *size, uint32_t *value, bool *doFuzz);
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool staticTarget, uint64_t staticTargetPc);
    void onBlockEnd(S2EExecutionState *state, uint64_t pc, unsigned source_type);
    void onCrashHang(S2EExecutionState *state, uint32_t flag);
    void onTimer();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
