///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2020, Cyberhaven, Inc
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

#include <qapi/qmp/qstring.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <s2e/Plugins/Core/Events.h>
#include "Screenshot.h"

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Screenshot, "Screenshot S2E plugin", "", );

void Screenshot::initialize() {
    m_period = s2e()->getConfig()->getInt(getConfigKey() + ".period", 5);
    m_counter = 0;

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &Screenshot::onTimer));
}

void Screenshot::takeScreenShot(const std::string &fileName) {
    if (!g_sqi.upcalls.screendump) {
        getWarningsStream() << "Screenshot service not implemented";
        return;
    }

    auto ret = g_sqi.upcalls.screendump(fileName.c_str());
    if (ret < 0) {
        getWarningsStream() << "Could not save screenshot to " << fileName << "\n";
    }
}

std::string Screenshot::takeScreenShot(S2EExecutionState *state) {
    std::stringstream filename;
    filename << "screenshot" << state->getID() << ".png";
    std::string outputFile = s2e()->getOutputFilename(filename.str());
    takeScreenShot(outputFile);

    return filename.str();
}

void Screenshot::onTimer() {
    if (!g_s2e_state) {
        return;
    }

    if ((m_counter % m_period) == 0) {
        std::string outputFile = takeScreenShot(g_s2e_state);
        if (monitor_ready()) {
            Events::PluginData data;
            QString *str = qstring_from_str(outputFile.c_str());
            data.push_back(std::make_pair("filename", QOBJECT(str)));
            Events::emitQMPEvent(this, data);
        }
    }

    ++m_counter;
}

void Screenshot::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_SCREENSHOT_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_SCREENSHOT_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case TAKE_SCREENSHOT:
            takeScreenShot(state);
            break;
        default:
            getWarningsStream(state) << "Unknown command " << command.Command << "\n";
            break;
    }
}

} // namespace plugins
} // namespace s2e
