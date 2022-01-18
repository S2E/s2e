///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef S2E_CORE_PLUGIN_H
#define S2E_CORE_PLUGIN_H

#include <klee/Expr.h>
#include <s2e/Plugin.h>

#include <inttypes.h>
#include <klee/Memory.h>
#include <vector>

#include <klee/Common.h>
#include <s2e/s2e_libcpu_coreplugin.h>

extern "C" {
typedef struct TranslationBlock TranslationBlock;
}

namespace klee {
class ExecutionState;
}

namespace s2e {

class S2EExecutionState;

///
/// A type of a signal emitted on instruction execution. Instances of this signal will be dynamically created and
/// destroyed on demand during translation.
///
typedef sigc::signal<void, S2EExecutionState *, uint64_t /* PC */> ExecutionSignal;

class CorePlugin : public Plugin {
    S2E_PLUGIN

private:
    void onInitializationCompleteCb(S2EExecutionState *state);

public:
    CorePlugin(S2E *s2e) : Plugin(s2e) {
    }

    enum class symbolicAddressReason { MEMORY, PC };

    void initialize();

    // clang-format off

    ///
    /// \brief Emitted when there are no more states to run and S2E is going to shutdown.
    ///
    /// The engine calls this signal before plugins are destroyed. This gives a chance for plugins to clean up their
    /// state.
    ///
    sigc::signal<void> onEngineShutdown;


    ///
    /// Signal that is emitted on beginning and end of code generation for each translation block.
    ///
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState*,
                 TranslationBlock*,
                 uint64_t /* block PC */>
        onTranslateBlockStart;

    ///
    /// Signal that is emitted upon end of a translation block. If the end is a conditional branch, it is emitted for
    /// both outcomes.
    ///
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState*,
                 TranslationBlock*,
                 uint64_t /* ending instruction PC */,
                 bool /* static target is valid */,
                 uint64_t /* static target PC */>
        onTranslateBlockEnd;

    ///
    /// Signal that is emitted when the translator finishes translating the block.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 TranslationBlock*,
                 uint64_t /* ending instruction PC */>
        onTranslateBlockComplete;

    ///
    /// Signals that are emitted on code generation for each instruction.
    ///
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState*,
                 TranslationBlock*,
                 uint64_t /* instruction PC */>
        onTranslateInstructionStart, onTranslateInstructionEnd;

    ///
    /// \brief Signal that is emitted at the end of "special" instructions.
    ///
    /// These special instructions include syscalls, immediate push instructions and reading rdtsc.
    ///
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState*,
                 TranslationBlock*,
                 uint64_t /* instruction PC */,
                 enum special_instruction_t  /* instruction type */,
                 const special_instruction_data_t * /* instruction data */>
        onTranslateSpecialInstructionEnd;

    ///
    /// Triggered \b after each instruction is translated to notify plugins of which registers are used by the
    /// instruction.
    ///
    /// Each bit of the mask corresponds to one of the registers of the architecture (e.g., R_EAX, R_ECX, etc).
    ///
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState* /* current state */,
                 TranslationBlock*,
                 uint64_t /* program counter of the instruction */,
                 uint64_t /* registers read by the instruction */,
                 uint64_t /* registers written by the instruction */,
                 bool /* instruction accesses memory */>
          onTranslateRegisterAccessEnd;

    ///
    /// Signal that is emitted on code generation for each jump instruction.
    ///
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState*,
                 TranslationBlock*,
                 uint64_t /* instruction PC */,
                 int /* jump type */>
        onTranslateJumpStart;

    ///
    /// Signal that is emitted on code generation for each indirect CTI instruction.
    ///
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState*,
                 TranslationBlock*,
                 uint64_t /* instruction PC */,
                 int /* rm */,
                 int /* op */,
                 int /* offset */>
        onTranslateICTIStart;

    ///
    /// Signal that is emitted on code generation for LEA instructions with a RIP-relative offset.
    ///
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState*,
                 TranslationBlock*,
                 uint64_t /* instruction PC */,
                 uint64_t /* target address */>
        onTranslateLeaRipRelative;

    ///
    /// Signal that is emitted upon exception.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 unsigned /* Exception Index */,
                 uint64_t /* PC */>
        onException;

    ///
    /// Signal that is emitted when custom opcode is detected.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 uint64_t /* arg */>
        onCustomInstruction;

    ///
    /// Signal emitted right before an INT xxx instruction is translated.
    ///
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState* /* current state */,
                 TranslationBlock*,
                 uint64_t /* program counter of the instruction */,
                 unsigned /* the interrupt vector */>
        onTranslateSoftInterruptStart;

    ///
    /// Signal that is emitted before accessing memory at symbolic address.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 klee::ref<klee::Expr> /* virtual address */,
                 klee::ref<klee::Expr> /* value */,
                 bool /* is write */>
        onBeforeSymbolicDataMemoryAccess;

    ///
    /// \brief Signal that is emitted on each memory access.
    ///
    /// Valid \c flags are defined in s2e_libcpu_coreplugin.h (\c MEM_TRACE_FLAG_*). Note that this signal is still not
    /// emitted for code.
    ///
    /// Important: when the \c MEM_TRACE_FLAG_PRECISE is not set, the reported program counter in the execution state
    /// is not synchronized and the handler must not attempt to exit the cpu loop or tweak the control flow.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 klee::ref<klee::Expr> /* virtual address */,
                 klee::ref<klee::Expr> /* host address */,
                 klee::ref<klee::Expr> /* value */,
                 unsigned /* flags */>
        onAfterSymbolicDataMemoryAccess;

    ///
    /// \brief Signal emitted before handling a memory address.
    ///
    /// \li The concrete address is one example of an address that satisfies the constraints.
    /// \li The concretize flag can be set to ask the engine to concretize the address.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 klee::ref<klee::Expr> /* virtual address */,
                 uint64_t /* concrete address */,
                 bool& /* concretize */,
                 CorePlugin::symbolicAddressReason /* reason */>
        onSymbolicAddress;

    ///
    /// Optimized signal for concrete accesses.
    ///
    /// Valid \c flags are defined in s2e_libcpu_coreplugin.h (\c MEM_TRACE_FLAG_*).
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 uint64_t /* virtual address */,
                 uint64_t /* value */,
                 uint8_t /* size */,
                 unsigned /* flags */>
        onConcreteDataMemoryAccess;

    ///
    /// Signals that are emitted on each port access.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 klee::ref<klee::Expr> /* port */,
                 klee::ref<klee::Expr> /* value */,
                 bool /* is write */>
        onPortAccess;

    ///
    // Emitted when a symbolic variable is created.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 const std::string & /* orignal name */,
                 const std::vector<klee::ref<klee::Expr>>&, /* expr */
                 const klee::ArrayPtr&>
        onSymbolicVariableCreation;

    ///
    /// Emitted periodically every 1000 ms.
    ///
    sigc::signal<void> onTimer;

    ///
    /// Signal emitted when the state is forked.
    ///
    sigc::signal<void,
                 S2EExecutionState* /* original state */,
                 const std::vector<S2EExecutionState*>& /* new states */,
                 const std::vector<klee::ref<klee::Expr>>& /* new conditions */>
        onStateFork;

    ///
    /// \brief This signal is emitted by the load balancer
    /// after it forks an S2E instance that contains
    /// one or more states copied from the parent, which
    /// forces an assignment of a new GUID.
    ///
    /// The signal is only emitted by the parent instance.
    ///
    /// The signal is used by the execution tracer
    /// plugin in order to make sure the trace contains
    /// a well-formed tree.
    ///
    sigc::signal<void, S2EExecutionState* /* state */,
                 uint64_t /* newGuid */>
        onStateGuidAssignment;

    ///
    /// Signal that is emitted when two states are merged.
    //
    sigc::signal<void,
                 S2EExecutionState* /* destination */,
                 S2EExecutionState* /* source */>
        onStateMerge;

    ///
    /// Signal that is emitted when we change states.
    ///
    sigc::signal<void,
                 S2EExecutionState*, /* current state */
                 S2EExecutionState* /* next state */>
        onStateSwitch;

    ///
    /// Triggered whenever a state is killed.
    ///
    sigc::signal<void, S2EExecutionState*> onStateKill;


    ///
    /// The executor emits this signal when it is about to fork a process. This is the last chance to stop it.
    ///
    /// Plugins set the pointer to \c true to allow forking to proceed.
    ///
    sigc::signal<void,
                 bool* /* allow forking */>
        onProcessForkDecide;


    ///
    /// \brief The executor emits this signal when it is about to fork a new state. This is the last chance to stop it.
    ///
    /// Note that this signal may be emitted when executing program instructions that are \b not necessarily branch
    /// instructions. For example, when dereferencing symbolic memory a number of helper functions are called (see
    /// \c TCGLLVMTranslator::initialzeHelpers) which may also cause fork branches. Depending on: the program
    /// instruction; memory accessed; and helper functions called, this may cause \c onStateForkDecide to be emitted
    /// multiple times for the same execution of a program instruction.
    ///
    /// Some optimization is performed so that the signal is \b not emitted when the fork condition is a constant
    /// expression (see \c S2EExecutor::fork). However, there may still be instances when the \c onStateForkDecide
    /// signal is emitted and fork branches are not actually guaranteed to occur (e.g. the constraint solver may decide
    /// not to fork branches).
    ///
    /// It is up to the signal handler to handle these cases. The signal handler <b>must not</b> assume that:
    ///
    ///   \li The fork is occurring at a branch instruction in the program code
    ///   \li The fork will actually occur, even if the pointer is set to \c true (ultimately this is up to the
    ///       constraint solver)
    ///   \li The signal will only be emitted once when a program instruction that \a may fork is executed.
    ///
    /// Plugins set the pointer to \c true to allow forking to proceed. By default this is set to \c true.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 const klee::ref<klee::Expr>& /*condition*/,
                 bool& /* allow forking */>
        onStateForkDecide;


    ///
    /// Signal emitted when spawning a new S2E process.
    ///
    sigc::signal<void,
                 bool /* prefork */,
                 bool /* is child */,
                 unsigned /* parent process ID */>
        onProcessFork;

    ///
    /// \brief Signal emitted when the load balancing needs to terminate states in the parent or the child.
    ///
    /// This signal allows plugins to change the default policy of splitting them in half by moving/copying the states
    /// in the desired sets.
    ///
    sigc::signal<void,
                 klee::StateSet& /* parent */,
                 klee::StateSet& /* child */>
        onStatesSplit;

    ///
    /// Signal emitted when a new S2E process was spawned and all parent states were removed from the child and child
    /// states removed from the parent.
    //
    sigc::signal<void,
                 bool /* is child */>
        onProcessForkComplete;

    ///
    /// Signal that is emitted upon TLB miss.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 uint64_t /* address */,
                 bool /* is write */>
        onTlbMiss;

    ///
    /// Signal that is emitted upon page fault.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 uint64_t /* address */,
                 bool /* is write */>
        onPageFault;

    ///
    /// \brief Emitted when the current execution privilege level was changed (e.g., kernel-mode to user-mode).
    ///
    /// The meaning of the current and previous privilege level may depend on the architecutre.
    ///
    sigc::signal<void,
                 S2EExecutionState* /* current state */,
                 unsigned /* previous level */,
                 unsigned /* current level */>
        onPrivilegeChange;

    ///
    /// \brief The current page directory was changed.
    ///
    /// This may occur, e.g., when the OS swaps address spaces. The addresses correspond to physical addresses.
    ///
    sigc::signal<void,
                 S2EExecutionState* /* current state */,
                 uint64_t /* previous page directory base */,
                 uint64_t /* current page directory base */>
        onPageDirectoryChange;

    ///
    /// S2E completed initialization and is about to enter the main execution loop for the first time.
    ///
    sigc::signal<void,
                 S2EExecutionState*>
        onInitializationComplete;

    ///
    /// \brief Exposes the equivalent searcher API call to S2E plugins.
    ///
    /// Plugins can cleanup their structures with this signal. The subscribers <b>MUST NOT</b> throw exceptions.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 const klee::StateSet& /* added states */,
                 const klee::StateSet& /* removed states */>
        onUpdateStates;

    ///
    /// Emitted when the \c klee::AddressSpace is changed.
    ///
    sigc::signal<void,
                 S2EExecutionState*,
                 const klee::ObjectKey &,
                 const klee::ObjectStateConstPtr & /* old state */,
                 const klee::ObjectStatePtr &/* new state */>
        onAddressSpaceChange;

    ///
    /// Emitted when a function call return instruction is translated.
    ///
    sigc::signal<void,
                S2EExecutionState*,
                uint64_t /* PC */,
                bool /* is call */,
                bool * /* instrument */>
        onCallReturnTranslate;

    // clang-format on
};

} // namespace s2e

#endif // S2E_CORE_PLUGIN_H
