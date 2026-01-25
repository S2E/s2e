///
/// Copyright (C) 2026, Vitaly Chipounov
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

#ifndef KLEE_STATEMANAGER_H
#define KLEE_STATEMANAGER_H

#include <klee/Searcher.h>

namespace klee {

class StateManager : public Searcher {
private:
    Searcher *m_searcher = nullptr;
    StateSet m_states;

public:
    virtual ~StateManager() = default;

    ExecutionStatePtr selectState() {
        assert(m_searcher && "No searcher set");
        auto ret = m_searcher->selectState();
        assert(m_states.find(ret) != m_states.end() && "Selected state is not managed");
        return ret;
    }

    void addState(klee::ExecutionStatePtr state) {
        m_states.insert(state);

        if (m_searcher) {
            m_searcher->addState(state);
        }
    }

    void removeState(klee::ExecutionStatePtr state) {
        if (m_searcher) {
            m_searcher->removeState(state);
        }

        m_states.erase(state);
    }

    bool empty() {
        auto ret = m_states.empty();
        assert(ret == m_states.empty());
        return ret;
    }

    void setSearcher(Searcher *searcher) {
        m_searcher = searcher;
    }

    Searcher *searcher() const {
        return m_searcher;
    }

    const StateSet &states() const {
        return m_states;
    }
};

} // namespace klee

#endif // KLEE_STATEMANAGER_H