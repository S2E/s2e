///
/// Copyright (C) 2016, Cyberhaven
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

#ifndef S2E_PLUGINS_MultiSearcher_H
#define S2E_PLUGINS_MultiSearcher_H

#include <klee/Searcher.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>

#include <map>

namespace s2e {
namespace plugins {

class MultiSearcher : public Plugin, public klee::Searcher {
    S2E_PLUGIN

private:
    typedef std::map<std::string, klee::Searcher *> Searchers;

    Searchers m_searchers;
    klee::Searcher *m_currentSearcher;

    void onInitComplete(S2EExecutionState *state);

public:
    MultiSearcher(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    bool registerSearcher(const std::string &name, klee::Searcher *searcher);
    bool selectSearcher(const std::string &name);

    virtual klee::ExecutionState &selectState();

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty();

private:
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MultiSearcher_H
