///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
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
#include <s2e/Utils.h>

#include "Example.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Example, "Example S2E plugin", "", );

void Example::initialize() {
    m_traceBlockTranslation = s2e()->getConfig()->getBool(getConfigKey() + ".traceBlockTranslation");

    m_traceBlockExecution = s2e()->getConfig()->getBool(getConfigKey() + ".traceBlockExecution");

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this, &Example::slotTranslateBlockStart));
}

void Example::slotTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                      uint64_t pc) {
    if (m_traceBlockTranslation) {
        getDebugStream(state) << "Translating block at " << hexval(pc) << "\n";
    }

    if (m_traceBlockExecution) {
        signal->connect(sigc::mem_fun(*this, &Example::slotExecuteBlockStart));
    }
}

void Example::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc) {
    getDebugStream(state) << "Executing block at " << hexval(pc) << "\n";
}

} // namespace plugins
} // namespace s2e
