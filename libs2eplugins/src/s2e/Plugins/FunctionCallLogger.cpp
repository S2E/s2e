///
/// Copyright (C) 2024, Yongheng Chen
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

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>

#include "FunctionCallLogger.h"

namespace s2e {
namespace plugins {

namespace {

//
// This class can optionally be used to store per-state plugin data.
//
// Use it as follows:
// void FunctionCallLogger::onEvent(S2EExecutionState *state, ...) {
//     DECLARE_PLUGINSTATE(FunctionCallLoggerState, state);
//     plgState->...
// }
//
class FunctionCallLoggerState: public PluginState {
    // Declare any methods and fields you need here

public:
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new FunctionCallLoggerState();
    }

    virtual ~FunctionCallLoggerState() {
        // Destroy any object if needed
    }

    virtual FunctionCallLoggerState *clone() const {
        return new FunctionCallLoggerState(*this);
    }
};

}

S2E_DEFINE_PLUGIN(FunctionCallLogger, "Describe what the plugin does here", "", );

void FunctionCallLogger::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    FunctionMonitor *monitor = s2e()->getPlugin<FunctionMonitor>();
    monitor->onCall.connect(sigc::mem_fun(*this, &FunctionCallLogger::onCall));
}

void FunctionCallLogger::onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                     const ModuleDescriptorConstPtr &dest, uint64_t callerPc, uint64_t calleePc,
                     const FunctionMonitor::ReturnSignalPtr &returnSignal) {
    auto module = m_detector->getCurrentDescriptor(state);
    /*
    if (!module) {
        // Not in the binary.
        return;
    }
    */
    // getDebugStream(state) << "Calling function from: " << hexval(callerPc) << " to " << hexval(calleePc) << "\n";
}


void FunctionCallLogger::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize)
{
    S2E_FUNCTIONCALLLOGGER_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_FUNCTIONCALLLOGGER_COMMAND size\n";
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
