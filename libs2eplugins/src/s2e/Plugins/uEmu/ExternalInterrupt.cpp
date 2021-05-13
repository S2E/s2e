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

#include "ExternalInterrupt.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ExternalInterrupt, "trigger and record external interrupts", "ExternalInterrupt");

class ExternalInterruptState : public PluginState {
private:
    typedef llvm::DenseMap<uint32_t, uint32_t> TBCounts;

    uint64_t tb_count;
    uint64_t re_tb_count;
    uint64_t new_tb_count;
    std::vector<uint32_t> last_irqs_bitmap;
    std::map<uint32_t /*external irq no*/, uint32_t /* count */> pirqs_map;
    std::map<uint32_t /* external irq no */, bool /*enable*/> active_irqs;
    bool disable_systick; // per state
    bool enable_interrupt;
    TBCounts new_tb_map;

public:
    ExternalInterruptState() {
        tb_count = 0;
        re_tb_count = 0;
        new_tb_map.clear();
        pirqs_map.clear();
        disable_systick = true;
        enable_interrupt = false;
        last_irqs_bitmap.push_back(0);
        last_irqs_bitmap.push_back(0);
    }

    virtual ~ExternalInterruptState() {
    }

    static PluginState *factory(Plugin *, S2EExecutionState *) {
        return new ExternalInterruptState();
    }

    ExternalInterruptState *clone() const {
        return new ExternalInterruptState(*this);
    }

    void inc_tb_num(uint32_t cur_pc) {
        ++tb_count;
        if (new_tb_map[cur_pc] < 1) {
            ++new_tb_map[cur_pc];
            ++new_tb_count;
            re_tb_count = 0;
        } else {
            ++re_tb_count;
        }
    }

    uint64_t get_tb_num() {
        return tb_count;
    }

    uint64_t get_newtb_num() {
        return new_tb_count;
    }

    uint64_t get_rettb_num() {
        return re_tb_count;
    }

    void set_systick_flag(bool systick_cmp_flag) {
        disable_systick = systick_cmp_flag;
    }

    bool get_systick_flag() {
        return disable_systick;
    }

    void set_enableinterrupt_flag(bool enableinterrupt) {
        enable_interrupt = enableinterrupt;
    }

    bool get_enableinterrupt_flag() {
        return enable_interrupt;
    }

    void insert_lastirqs_bitmap(std::vector<uint32_t> irqsbitmap) {
        last_irqs_bitmap = irqsbitmap;
    }

    std::vector<uint32_t> get_lastirqs_bitmap() {
        return last_irqs_bitmap;
    }

    void update_activeirqs(std::map<uint32_t, bool> activeirqs) {
        active_irqs = activeirqs;
    }

    void insert_activeirqs(uint32_t irq_no) {
        active_irqs[irq_no] = true;
    }

    std::map<uint32_t, bool> get_activeirqs() {
        return active_irqs;
    }
};

void ExternalInterrupt::initialize() {
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &ExternalInterrupt::onTranslateBlockStart));

    bool ok;
    tb_interval = s2e()->getConfig()->getInt(getConfigKey() + ".tbInterval", 2000, &ok);
    tb_scale = s2e()->getConfig()->getInt(getConfigKey() + ".BBScale", 30000, &ok);

    if (!ok) {
        getWarningsStream()
            << "Could not set correct limit repeat conditions count, count should be greater than two\n";
        return;
    } else {
        getDebugStream() << "trigger each external irq every " << tb_interval << " translation blocks"
                         << " total bb scale is " << tb_scale << "\n";
    }

    ConfigFile *cfg = s2e()->getConfig();
    auto disableirqs = cfg->getIntegerList(getConfigKey() + ".disableIrqs");
    foreach2 (it, disableirqs.begin(), disableirqs.end()) {
        getDebugStream() << "Add disable irqs = " << hexval(*it) << "\n";
        disable_irqs.push_back(*it);
    }
    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &ExternalInterrupt::onTimer));
    timer_ticks = 0;

    systick_disable_flag = s2e()->getConfig()->getBool(getConfigKey() + ".disableSystickInterrupt", false);
    if (systick_disable_flag) {
        systick_begin_point = s2e()->getConfig()->getInt(getConfigKey() + ".systickBeginPoint", 0x0, &ok);
        if (!ok) {
            getWarningsStream() << " systick begin point should be set!\n";
            return;
        } else {
            getInfoStream() << "systick begin point = " << hexval(systick_begin_point) << "\n";
        }
    }
}

void ExternalInterrupt::onTimer() {
    ++timer_ticks;
}

void ExternalInterrupt::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                              uint64_t pc) {
    signal->connect(sigc::mem_fun(*this, &ExternalInterrupt::onBlockStart));
}

std::map<uint32_t, bool> setActiveIrqs(std::vector<uint32_t> irqs_bitmap) {
    std::map<uint32_t /* external irq no */, bool /*enable*/> active_irqs;

    for (int i = 0; i < irqs_bitmap.size(); i++) {
        for (int j = 0; j < 32; j++) {
            if (irqs_bitmap[i] & (1 << j)) {
                active_irqs[i * 32 + j] = true;
            }
        }
    }
    return active_irqs;
}

void ExternalInterrupt::onBlockStart(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(ExternalInterruptState, state);

    if (plgState->get_systick_flag() == true && systick_disable_flag) {
        s2e()->getExecutor()->disableSystickInterrupt(0);
        if (pc == systick_begin_point) {
            getDebugStream() << "enable systick at " << pc << "\n";
            plgState->set_systick_flag(false);
            s2e()->getExecutor()->disableSystickInterrupt(7);
        }
    }

    plgState->inc_tb_num(pc);

    if (g_s2e_cache_mode) {
        if (!g_s2e_fast_concrete_invocation) {
            // getWarningsStream() <<" should not happen sym pc = " << hexval(pc) << "\n";
            return;
        }
    }

    if (!g_s2e_cache_mode) { // learning mode only
        // in case no external irqs
        if (tb_interval < 0.0334 * tb_scale) {
            tb_interval = tb_interval * 2;
        }

        // trigger external irqs later on
        // TODO: change to the scale of tb_termination
        if ((plgState->get_rettb_num() > 0.5 * tb_scale) && !plgState->get_enableinterrupt_flag() &&
            plgState->get_newtb_num() > 0.01 * tb_scale) {
            getDebugStream() << "Now enable external irq re tb number = " << plgState->get_tb_num() << "\n";
            plgState->set_enableinterrupt_flag(true);
            return;
        }

        if (!plgState->get_enableinterrupt_flag()) {
            return;
        }

        if (plgState->get_tb_num() % tb_scale == 0) {
            getInfoStream() << "current pc at = " << hexval(pc) << " execution time of each " << tb_scale
                                << " blocks is " << hexval(timer_ticks) << "\n";
        }
    }

    if (plgState->get_tb_num() % 10000000 == 0) {
        getInfoStream() << "current pc at = " << hexval(pc) << " execution time of each 10,000,000 basic blocks is "
                            << timer_ticks << "s\n";
    }

    std::vector<uint32_t> irqs_bitmap;
    std::vector<uint32_t> last_irqs_bitmap;
    if (plgState->get_tb_num() % tb_interval == 0) {
        irqs_bitmap.push_back(s2e()->getExecutor()->getActiveExternalInterrupt(0));
        getDebugStream() << "external bit map = " << hexval(irqs_bitmap[0]) << "\n";
        irqs_bitmap.push_back(s2e()->getExecutor()->getActiveExternalInterrupt(4));
        getDebugStream() << "external bit map 2 = " << hexval(irqs_bitmap[1]) << "\n";
        irqs_bitmap.push_back(s2e()->getExecutor()->getActiveExternalInterrupt(8));
        getDebugStream() << "external bit map 3 = " << hexval(irqs_bitmap[2]) << "\n";

        last_irqs_bitmap = plgState->get_lastirqs_bitmap();
        for (int k = 0; k < irqs_bitmap.size(); k++) {
            if (last_irqs_bitmap[k] != irqs_bitmap[k]) {
                getInfoStream() << "active irq has changed\n";
                getInfoStream() << "external irq bit map = " << hexval(irqs_bitmap[0]) << "\n";
                getInfoStream() << "external irq bit map = " << hexval(irqs_bitmap[1]) << "\n";
                getInfoStream() << "external irq bit map = " << hexval(irqs_bitmap[2]) << "\n";
                plgState->insert_lastirqs_bitmap(irqs_bitmap);
                plgState->update_activeirqs(setActiveIrqs(irqs_bitmap));
                break;
            }
        }

        int i = 0;
        for (auto it : plgState->get_activeirqs()) {
            if ((plgState->get_tb_num() / tb_interval) % plgState->get_activeirqs().size() == i) {
                if (state->regs()->getInterruptFlag() && state->regs()->getExceptionIndex() == (it.first + 16)) {
                    getDebugStream() << i << " should not happen pc = " << hexval(pc) << "irq num"
                                     << state->regs()->getExceptionIndex() << "\n";
                    ++i;
                    continue;
                }
                if (!g_s2e_cache_mode) {
                    // plgState->cachepirq(it.first);
                    getInfoStream() << i << " trigger external irq " << it.first << " total irq number is "
                                        << plgState->get_activeirqs().size()
                                        << "total tb num = " << plgState->get_tb_num() << "\n";
                    if (std::find(disable_irqs.begin(), disable_irqs.end(), it.first) == disable_irqs.end()) {
                        ++i;
                        s2e()->getExecutor()->setExternalInterrupt(it.first);
                    } else {
                        ++i;
                        continue;
                    }
                } else {
                    if (std::find(disable_irqs.begin(), disable_irqs.end(), it.first) == disable_irqs.end()) {
                        getDebugStream() << " trigger external irq " << it.first
                                         << "total tb num = " << plgState->get_tb_num() << "\n";
                        ++i;
                        s2e()->getExecutor()->setExternalInterrupt(it.first);
                    } else {
                        ++i;
                        continue;
                    }
                }
            }
            ++i;
        } // each exteranl irq trigger
    }     // each interval
}

} // namespace plugins
} // namespace s2e
