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

#include "MyClient.h"

#include "s2e/ConfigFile.h"
#include "s2e/Plugins/InstructionTracker.h"
#include "s2e/S2E.h"
#include "s2e/Utils.h"
#include "fsigc++/fsigc++.h"

namespace s2e {
namespace plugins {

namespace {

// class InstructionTrackerState : public PluginState {
// private:
//     int m_count;
//
// public:
//     InstructionTrackerState() : m_count(0) {
//     }
//
//     virtual ~InstructionTrackerState() {
//         // Destroy any object if needed
//     }
//
//     static PluginState *factory(Plugin *p, S2EExecutionState *s) {
//         return new InstructionTrackerState();
//     }
//
//     virtual InstructionTrackerState *clone() const {
//         return new InstructionTrackerState(*this);
//     }
//
//     void increment() {
//         ++m_count;
//     }
//
//     int get() const {
//         return m_count;
//     }
// };

} // namespace

S2E_DEFINE_PLUGIN(MyClient, "Client plugin consuming InstructionTracker::onPeriodicEvent", "MyClient",
                  "InstructionTracker");

void MyClient::initialize() {
    InstructionTracker *itracker = s2e()->getPlugin<InstructionTracker>();
    if (!itracker) {
        s2e()->getWarningsStream() << "InstructionTracker plugin is not loaded. Not connecting the onPeriodicEvent.\n";
        return;
    }

    itracker->onPeriodicEvent.connect(sigc::mem_fun(*this, &MyClient::periodicHandler));
}

void MyClient::periodicHandler(S2EExecutionState *state, uint64_t pc) {
    s2e()->getInfoStream() << "MyClient::periodicHandler -- " << hexval(pc) << '\n';
}

void MyClient::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
}

} // namespace plugins
} // namespace s2e
