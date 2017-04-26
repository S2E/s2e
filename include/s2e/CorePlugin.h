///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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

/** A type of a signal emitted on instruction execution. Instances of this signal
    will be dynamically created and destroyed on demand during translation. */
typedef sigc::signal<void, S2EExecutionState *, uint64_t /* pc */> ExecutionSignal;

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
    /// \brief onEngineShutdown is emitted when there are no more states
    /// to run and S2E is going to shutdown.
    ///
    /// The engine calls this signal before plugins are destroyed.
    /// Gives a chance for plugins to clean up their state.
    ///
    sigc::signal<void> onEngineShutdown;


    /** Signal that is emitted on beginning and end of code generation
        for each translation block.
    */
    sigc::signal<void, ExecutionSignal*,
            S2EExecutionState*,
            TranslationBlock*,
            uint64_t /* block PC */>
            onTranslateBlockStart;

    /**
     * Signal that is emitted upon end of a translation block.
     * If the end is a conditional branch, it is emitted for both outcomes.
     */
    sigc::signal<void, ExecutionSignal*,
            S2EExecutionState*,
            TranslationBlock*,
            uint64_t /* ending instruction pc */,
            bool /* static target is valid */,
            uint64_t /* static target pc */>
            onTranslateBlockEnd;

    /**
     * Signal that is emitted when the translator finishes
     * translating the block.
     */
    sigc::signal<void, S2EExecutionState*,
            TranslationBlock*,
            uint64_t /* ending instruction pc */>
            onTranslateBlockComplete;


    /** Signal that is emitted on code generation for each instruction */
    sigc::signal<void, ExecutionSignal*,
            S2EExecutionState*,
            TranslationBlock*,
            uint64_t /* instruction PC */>
            onTranslateInstructionStart, onTranslateInstructionEnd;

    sigc::signal<void, ExecutionSignal*,
            S2EExecutionState*,
            TranslationBlock*,
            uint64_t /* instruction PC */,
            enum special_instruction_t  /* instruction type */>
            onTranslateSpecialInstructionEnd;

    /**
     *  Triggered *after* each instruction is translated to notify
     *  plugins of which registers are used by the instruction.
     *  Each bit of the mask corresponds to one of the registers of
     *  the architecture (e.g., R_EAX, R_ECX, etc).
     */
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState* /* current state */,
                 TranslationBlock*,
                 uint64_t /* program counter of the instruction */,
                 uint64_t /* registers read by the instruction */,
                 uint64_t /* registers written by the instruction */,
                 bool /* instruction accesses memory */>
          onTranslateRegisterAccessEnd;

    /** Signal that is emitted on code generation for each jump instruction */
    sigc::signal<void, ExecutionSignal*,
            S2EExecutionState*,
            TranslationBlock*,
            uint64_t /* instruction PC */,
            int /* jump_type */>
            onTranslateJumpStart;

    /** Signal that is emitted on code generation for each indirect CTI instruction */
    sigc::signal<void, ExecutionSignal*,
            S2EExecutionState*,
            TranslationBlock*,
            uint64_t /* instruction PC */,
            int /* rm */,
            int /* op */,
            int /* offset */ >
            onTranslateICTIStart;

    /** Signal that is emitted on code generation for LEA instruction with
        a rip-relative offset */
    sigc::signal<void, ExecutionSignal*,
            S2EExecutionState*,
            TranslationBlock*,
            uint64_t /* instruction PC */,
            uint64_t /* target address */>
            onTranslateLeaRipRelative;

    /** Signal that is emitted upon exception */
    sigc::signal<void, S2EExecutionState*,
            unsigned /* Exception Index */,
            uint64_t /* pc */>
            onException;

    /** Signal that is emitted when custom opcode is detected */
    sigc::signal<void, S2EExecutionState*,
            uint64_t  /* arg */
            >
            onCustomInstruction;

    /** Signal emitted right before an int xxx instruction is translated */
    sigc::signal<void,
                 ExecutionSignal*,
                 S2EExecutionState* /* current state */,
                 TranslationBlock*,
                 uint64_t /* program counter of the instruction */,
                 unsigned /* the interrupt vector */>
          onTranslateSoftInterruptStart;

    /** Signal that is emitted before accessing memory at symbolic address */
    sigc::signal<void, S2EExecutionState*,
                 klee::ref<klee::Expr> /* virtualAddress */,
                 klee::ref<klee::Expr> /* value */,
                 bool> /* isWrite */
            onBeforeSymbolicDataMemoryAccess;

    /** Signal that is emitted on each memory access */
    /* XXX: this signal is still not emitted for code */
    /* Important: when the MEM_TRACE_FLAG_PRECISE is not set,
       the reported program counter in the execution state is
       not synchronized and the handler must not attempt to exit the cpu loop
       or tweak the control flow */
    sigc::signal<void, S2EExecutionState*,
                 klee::ref<klee::Expr> /* virtualAddress */,
                 klee::ref<klee::Expr> /* hostAddress */,
                 klee::ref<klee::Expr> /* value */,
                 unsigned /* flags */>
            onAfterSymbolicDataMemoryAccess;

    /**
     * Signal emitted before handling a memory address.
     * - The concrete address is one example of an address that satisfies
     * the constraints.
     * - The concretize flag can be set to ask the engine to concretize the address.
     */
    sigc::signal<void, S2EExecutionState*,
                 klee::ref<klee::Expr> /* virtualAddress */,
                 uint64_t /* concreteAddress */,
                 bool & /* concretize */,
                 CorePlugin::symbolicAddressReason /* reason */ >
            onSymbolicAddress;

    /* Optimized signal for concrete accesses */
    sigc::signal<void, S2EExecutionState*,
                 uint64_t /* virtualAddress */,
                 uint64_t /* value */,
                 uint8_t /* size */,
                 unsigned /* flags */>
            onConcreteDataMemoryAccess;


    /** Signal that is emitted on each port access */
    sigc::signal<void, S2EExecutionState*,
                 klee::ref<klee::Expr> /* port */,
                 klee::ref<klee::Expr> /* value */,
                 bool /* isWrite */>
            onPortAccess;

    sigc::signal<void, S2EExecutionState*,
                 const std::string & /* orignal name */,
                 const std::vector<klee::ref<klee::Expr> > &, /* expr */
                 const klee::MemoryObject*,
                 const klee::Array*
                 >
            onSymbolicVariableCreation;

    sigc::signal<void> onTimer;

    /** Signal emitted when the state is forked */
    sigc::signal<void, S2EExecutionState* /* originalState */,
                 const std::vector<S2EExecutionState*>& /* newStates */,
                 const std::vector<klee::ref<klee::Expr> >& /* newConditions */>
            onStateFork;

    /** Signal that is emitted when two states are merged */
    sigc::signal<void, S2EExecutionState* /* destination */,
                 S2EExecutionState* /* source */>
            onStateMerge;

    sigc::signal<void,
                 S2EExecutionState*, /* currentState */
                 S2EExecutionState*> /* nextState */
            onStateSwitch;

    /**
     * Triggered whenever a state is killed
     */
    sigc::signal<void, S2EExecutionState*> onStateKill;


    /**
     * The executor emits this signal when it is about to fork a process.
     * Last chance to stop it.
     * Plugins set the pointer to true to allow forking to proceed.
     */
    sigc::signal<void, bool*> onProcessForkDecide;


    /**
     * The executor emits this signal when it is about to fork a new state.
     * Last chance to stop it.
     * Plugins set the pointer to true to allow forking to proceed.
     */
    sigc::signal<void, S2EExecutionState *, bool*> onStateForkDecide;


    /** Signal emitted when spawning a new S2E process */
    sigc::signal<void, bool /* prefork */,
                bool /* ischild */,
                unsigned /* parentProcId */>
            onProcessFork;

    /**
     * Signal emitted when the load balancing needs to terminate states in
     * the parent or the child. This allows plugins to change the default policy
     * of splitting them in half by moving/copying the states in
     * the desired sets.
     */
    sigc::signal<void,
                 klee::StateSet & /* parent */,
                 klee::StateSet & /* child */>
            onStatesSplit;

    /**
     * Signal emitted when a new S2E process was spawned and all
     * parent states were removed from the child and child states
     * removed from the parent.
     */
    sigc::signal<void, bool /* isChild */> onProcessForkComplete;


    /** Signal that is emitted upon TLB miss */
    sigc::signal<void, S2EExecutionState*, uint64_t, bool> onTlbMiss;

    /** Signal that is emitted upon page fault */
    sigc::signal<void, S2EExecutionState*, uint64_t, bool> onPageFault;

    /**
     * The current execution privilege level was changed (e.g., kernel-mode=>user-mode)
     * previous and current are privilege levels. The meaning of the value may
     * depend on the architecture.
     */
    sigc::signal<void,
                 S2EExecutionState* /* current state */,
                 unsigned /* previous level */,
                 unsigned /* current level */>
          onPrivilegeChange;

    /**
     * The current page directory was changed.
     * This may occur, e.g., when the OS swaps address spaces.
     * The addresses correspond to physical addresses.
     */
    sigc::signal<void,
                 S2EExecutionState* /* current state */,
                 uint64_t /* previous page directory base */,
                 uint64_t /* current page directory base */>
          onPageDirectoryChange;

    /**
     * S2E completed initialization and is about to enter
     * the main execution loop for the first time.
     */
    sigc::signal<void,
                 S2EExecutionState* /* current state */>
          onInitializationComplete;

    /**
     * Exposes the equivalent searcher API call to S2E plugins.
     * Plugins can cleanup their structures with this.
     * The subscribers MUST NOT throw exceptions.
     */
    sigc::signal<void,
                 S2EExecutionState* /* current state */,
                 const klee::StateSet & /* addedStates */,
                 const klee::StateSet & /* removedStates */>
          onUpdateStates;

    /**
     * Fired when the klee::AddressSpace is changed.
     */
    sigc::signal<void,
                 S2EExecutionState* /* current state */,
                 const klee::MemoryObject* /* *mo */,
                 const klee::ObjectState* /* *oldState */,
                 klee::ObjectState* /* *newState */>
          onAddressSpaceChange;


    sigc::signal<void,
                S2EExecutionState*,
                uint64_t /* pc */,
                bool /* isCall */,
                bool * /* instrument */>
          onCallReturnTranslate;

    // clang-format on
};

} // namespace s2e

#endif // S2E_CORE_PLUGIN_H
