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

#ifndef __S2E_SEARCHERS_COMMON__
#define __S2E_SEARCHERS_COMMON__

#include <s2e/S2EExecutionState.h>

#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

namespace s2e {
namespace plugins {

namespace searchers {

struct StatePriority {
    S2EExecutionState *state;
    int64_t priority;

    StatePriority() {
        state = nullptr;
        priority = 0;
    }

    StatePriority(S2EExecutionState *state, int64_t p) {
        this->state = state;

        /* State with a higher p get selected first */
        this->priority = p;
    }
};

struct state_t {};
struct priority_t {};

typedef boost::multi_index_container<
    StatePriority,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<boost::multi_index::tag<state_t>,
                                           BOOST_MULTI_INDEX_MEMBER(StatePriority, S2EExecutionState *, state)>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<priority_t>,
                                               BOOST_MULTI_INDEX_MEMBER(StatePriority, int64_t, priority)>>>
    MultiStates;

typedef MultiStates::index<state_t>::type StatesByPointer;
typedef MultiStates::index<priority_t>::type StatesByPriority;
} // namespace searchers
} // namespace plugins
} // namespace s2e

#endif
