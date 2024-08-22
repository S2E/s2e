//
// Copyright (c) 2020-2024 Kuan-Yen Chou. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation files
// (the "Software"), to deal with the Software without restriction,
// including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software,
// and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// * Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimers.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimers in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the names of Mimesis, University of Illinois Urbana-Champaign
//   nor the names of its contributors may be used to endorse or promote products
//   derived from this Software without specific prior written permission.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH
// THE SOFTWARE.
//

#ifndef S2E_PLUGINS_MIMESIS_H
#define S2E_PLUGINS_MIMESIS_H

#include <cstdint>
#include <string>
#include <vector>

#include "s2e/Plugin.h"
#include "s2e/S2E.h"
#include "s2e/S2EExecutionState.h"
#include "klee/Expr.h"
#include "klee/util/Ref.h"
#include "Core/BaseInstructions.h"
#include "OSMonitors/Linux/LinuxMonitor.h"
#include "OSMonitors/Support/ProcessExecutionDetector.h"
#include "libps/model.hpp"

namespace s2e {
namespace plugins {

class Mimesis : public Plugin {
    S2E_PLUGIN;

private:
    LinuxMonitor *_monitor = nullptr;
    BaseInstructions *_base_inst = nullptr;
    ProcessExecutionDetector *_proc_detector = nullptr;
    std::vector<std::string> _interfaces;
    ps::Model _model;

private:
    /**
     * S2E completed initialization and is about to enter the main execution loop for the first time.
     */
    void onInitializationComplete(S2EExecutionState *state);

    /**
     * The executor emits this signal when it is about to fork a new state. This is the last chance to stop it.
     *
     *
     * Note that this signal may be emitted when executing program instructions that are \b not necessarily branch
     * instructions. For example, when dereferencing symbolic memory a number of helper functions are called (see
     * \c TCGLLVMTranslator::initialzeHelpers) which may also cause fork branches. Depending on: the program
     * instruction; memory accessed; and helper functions called, this may cause \c onStateForkDecide to be emitted
     * multiple times for the same execution of a program instruction.
     *
     * Some optimization is performed so that the signal is \b not emitted when the fork condition is a constant
     * expression (see \c S2EExecutor::fork). However, there may still be instances when the \c onStateForkDecide
     * signal is emitted and fork branches are not actually guaranteed to occur (e.g. the constraint solver may decide
     * not to fork branches).
     *
     * It is up to the signal handler to handle these cases. The signal handler **must not** assume that:
     *   - The fork is occurring at a branch instruction in the program code
     *   - The fork will actually occur, even if the pointer is set to \c true (ultimately this is up to the constraint
     *   solver)
     *   - The signal will only be emitted once when a program instruction that \a may fork is executed.
     *
     * Plugins set the pointer to \c true to allow forking to proceed. By default this is set to \c true.
     */
    void onStateForkDecide(S2EExecutionState *state, const klee::ref<klee::Expr> &condition, bool &allow_forking);

    /**
     * Signal emitted when the state is forked.
     */
    void onStateFork(S2EExecutionState *original_state, const std::vector<S2EExecutionState *> &new_states,
                     const std::vector<klee::ref<klee::Expr>> &conditions);

    /**
     * Signal emitted when a custom opcode is detected.
     */
    void onCustomInstruction(S2EExecutionState *state, uint64_t opcode);

    /**
     * Signal that is emitted when two states are merged.
     */
    void onStateMerge(S2EExecutionState *destination, S2EExecutionState *source);

    /**
     * Signal that is emitted when we change states.
     */
    void onStateSwitch(S2EExecutionState *current_state, S2EExecutionState *next_state);

    /**
     * Triggered whenever a state is killed.
     */
    void onStateKill(S2EExecutionState *state);

    /**
     * Signal emitted before handling a memory address.
     *
     * - The concrete address is one example of an address that satisfies the constraints.
     * - The concretize flag can be set to ask the engine to concretize the address.
     */
    void onSymbolicAddress(S2EExecutionState *state, klee::ref<klee::Expr> virtual_addr, uint64_t concrete_addr,
                           bool &concretize, CorePlugin::symbolicAddressReason reason);

    /**
     * Signal that is emitted before accessing memory at symbolic address.
     */
    void onBeforeSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> virtual_addr,
                                          klee::ref<klee::Expr> value, bool is_write);

    /**
     * Signal that is emitted on each memory access.
     *
     * Valid \c flags are defined in s2e_libcpu_coreplugin.h (\c MEM_TRACE_FLAG_*). Note that this signal is still not
     * emitted for code.
     *
     * Important: when the \c MEM_TRACE_FLAG_PRECISE is not set, the reported program counter in the execution state
     * is not synchronized and the handler must not attempt to exit the cpu loop or tweak the control flow.
     */
    void onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> virtual_addr,
                                         klee::ref<klee::Expr> host_addr, klee::ref<klee::Expr> value, unsigned flags);

    /**
     * Optimized signal for concrete accesses.
     *
     * Valid \c flags are defined in s2e_libcpu_coreplugin.h (\c MEM_TRACE_FLAG_*).
     */
    void onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t virtual_addr, uint64_t value, uint8_t size,
                                    unsigned flags);

    /**
     * Signal emitted when the program under analysis has been loaded.
     */
    void onProcessLoad(S2EExecutionState *state, uint64_t page_dir, uint64_t pid, const std::string &proc_name);

    /**
     * Signal emitted when the program under analysis has been unloaded.
     */
    void onProcessUnload(S2EExecutionState *state, uint64_t page_dir, uint64_t pid, uint64_t return_code);

    /**
     * Emitted when there are no more states to run and S2E is going to shutdown.
     */
    void onEngineShutdown();

    std::string timestamp() const;

    /**
     * Get the program counter (PC/eip) from the current state.
     */
    uint64_t get_pc(S2EExecutionState *state) const;

    // /**
    //  * Start sending packets to the interface with the given `if_name`.
    //  */
    void send_packets_to(S2EExecutionState *state, const std::string &if_name) const;
    //
    // /**
    //  * Stop sending packets.
    //  */
    void stop_sending_packets(S2EExecutionState *state) const;

    void create_sym_var(S2EExecutionState *state, uintptr_t address, unsigned int size,
                        const std::string &var_name) const;
    /**
     * Mimesis custom instruction: user_recv, invoked when the userspace application receives incoming packets.
     */
    void user_recv(S2EExecutionState *state);
    /**
     * Mimesis custom instruction: user_send, invoked when the userspace application sends outgoing packets.
     */
    void user_send(S2EExecutionState *state);
    /**
     * Record the trace of the current execution path, update the model, and
     * clear the plugin state for the current execution path.
     */
    void record_trace(S2EExecutionState *state, const klee::ref<klee::Expr> egress_intf,
                      const klee::ref<klee::Expr> egress_pkt);
    
    void kernel_recv(S2EExecutionState *state);
    void kernel_send(S2EExecutionState *state);
    

public:
    Mimesis(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    ~Mimesis();
};

class MimesisState : public PluginState {
private:
    int depth;
    klee::ref<klee::Expr> ingress_intf;
    klee::ref<klee::Expr> ingress_pkt;
    friend class Mimesis;

public:
    MimesisState() : depth(0) {
    }
    virtual ~MimesisState() {
    }
    virtual PluginState *clone() const {
        return new MimesisState(*this);
    }
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new MimesisState();
    }
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MIMESIS_H
