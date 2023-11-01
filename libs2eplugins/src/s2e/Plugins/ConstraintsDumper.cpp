///
/// Copyright (C) 2023, Yongheng Chen
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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>

#include "ConstraintsDumper.h"

namespace s2e {
namespace plugins {

namespace {

//
// This class can optionally be used to store per-state plugin data.
//
// Use it as follows:
// void ConstraintsDumper::onEvent(S2EExecutionState *state, ...) {
//     DECLARE_PLUGINSTATE(ConstraintsDumperState, state);
//     plgState->...
// }
//
class ConstraintsDumperState : public PluginState {
    // Declare any methods and fields you need here

public:
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new ConstraintsDumperState();
    }

    virtual ~ConstraintsDumperState() {
        // Destroy any object if needed
    }

    virtual ConstraintsDumperState *clone() const {
        return new ConstraintsDumperState(*this);
    }
};

} // namespace

S2E_DEFINE_PLUGIN(ConstraintsDumper, "The plugin dumps all the symbolic constraints for each state at fork", "", );

void ConstraintsDumper::initialize() {
    m_detector_ = s2e()->getPlugin<ModuleExecutionDetector>();
    enabled_ = s2e()->getConfig()->getBool(getConfigKey() + ".enable", false, nullptr);
    if (enabled_) {
        if (m_detector_ == nullptr) {
            getWarningsStream() << "ConstraintsDumper requires ModuleExecutionDetector\n";
            exit(-1);
        }
        s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &ConstraintsDumper::onFork));
    }
    output_stream_ = s2e()->openOutputFile(output_file_name_);
    if(output_stream_ == nullptr) {
        getWarningsStream() << "Cannot open file " << output_file_name_ << " for dumping constraints\n";
        exit(-1);
    }
}

void ConstraintsDumper::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                         const std::vector<klee::ref<klee::Expr>> &newConditions) {
    auto module = m_detector_->getCurrentDescriptor(state);
    if (!module) {
        return;
    }

    for(const auto new_state: newStates) {
        *output_stream_ << "State ID: " << new_state->getID() << "\n";
        new_state->dumpQuery(*output_stream_);
    }
}

void ConstraintsDumper::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                               uint64_t guestDataSize) {
    S2E_CONSTRAINTSDUMPER_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_CONSTRAINTSDUMPER_COMMAND size\n";
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
