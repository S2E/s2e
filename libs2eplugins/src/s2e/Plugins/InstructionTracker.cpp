///
/// Copyright (C) 2024, Kuan-Yen Chou
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

#include "InstructionTracker.h"

#include "s2e/ConfigFile.h"
#include "s2e/S2E.h"
#include "s2e/Utils.h"
#include "fsigc++/fsigc++.h"

namespace s2e {
namespace plugins {

namespace {

class InstructionTrackerState : public PluginState {
private:
    int m_count;

public:
    InstructionTrackerState() : m_count(0) {
    }

    virtual ~InstructionTrackerState() {
        // Destroy any object if needed
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new InstructionTrackerState();
    }

    virtual InstructionTrackerState *clone() const {
        return new InstructionTrackerState(*this);
    }

    void increment() {
        ++m_count;
    }

    int get() const {
        return m_count;
    }
};

} // namespace

S2E_DEFINE_PLUGIN(InstructionTracker, "Tracking instructions. S2E tutorial", "InstructionTracker", );

void InstructionTracker::initialize() {
    m_address = s2e()->getConfig()->getInt(getConfigKey() + ".addressToTrack");

    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &InstructionTracker::onTranslateInstruction));
}

void InstructionTracker::onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                                uint64_t pc) {
    // s2e()->getInfoStream() << "onTranslateInstruction " << hexval(pc) << "\n";

    if (m_address == pc) {
        s2e()->getInfoStream() << "Registering onInstructionExecution for " << hexval(pc) << "\n";
        // Found the interesting address. Ask S2E to invoke our callback when
        // the address is actually executed.
        signal->connect(sigc::mem_fun(*this, &InstructionTracker::onInstructionExecution));
    }
}

// This callback is triggered only when the instruction is executed.
// It incurs no overhead for all other instructions.
void InstructionTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
    // This declares the plgState variable of type InstructionTrackerState. It
    // automatically retrieves the right plugin state attached to the specified
    // execution state.
    DECLARE_PLUGINSTATE(InstructionTrackerState, state);

    s2e()->getDebugStream() << "Executing instruction at " << hexval(pc) << '\n';
    // The plugins can arbitrarily modify/observe the current execution state
    // via the execution state pointer. Plugins can also call the s2e() method
    // to use the S2E API.

    plgState->increment();

    // Trigger the exported event.
    if ((plgState->get() % 10) == 0) {
        onPeriodicEvent.emit(state, pc);
    }
}

void InstructionTracker::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                                uint64_t guestDataSize) {
    S2E_INSTRUCTIONTRACKER_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_INSTRUCTIONTRACKER_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        // TODO: add custom commands here
        case COMMAND_1:
            break;
        default:
            getWarningsStream(state) << "Unknown command " << command.Command << "\n";
            break;
    }
}

} // namespace plugins
} // namespace s2e
