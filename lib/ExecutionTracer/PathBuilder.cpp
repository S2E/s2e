///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <cassert>
#include <iostream>
#include <ostream>
#include <s2e/Plugins/ExecutionTracers/TraceEntries.h>
#include <stack>
#include "Path.h"

//#define DEBUG_PB

namespace s2etools {

PathSegment::PathSegment(PathSegment *parent, uint32_t stateId, uint64_t forkPc) {
    m_StateId = stateId;
    m_ForkPc = forkPc;
    m_Parent = NULL;

    if (parent) {
        m_Parent = parent;
        PathSegmentList::const_iterator it;
        for (it = m_Parent->m_Children.begin(); it != m_Parent->m_Children.end(); ++it) {
            // The parent can appear only once in the set of its children
            assert((*it)->m_StateId != stateId);
        }
        m_Parent->m_Children.push_back(this);
    }
}

PathSegment::~PathSegment() {
    deleteState();
}

void PathSegment::deleteState() {
    PathSegmentStateMap::iterator it;
    for (it = m_SegmentState.begin(); it != m_SegmentState.end(); ++it) {
        delete (*it).second;
    }
    m_SegmentState.clear();
}

unsigned PathSegment::getIndexInParent() const {
    if (!m_Parent) {
        return 0;
    }

    const PathSegmentList &c = m_Parent->getChildren();
    PathSegmentList::const_iterator it;
    unsigned i = 0;
    for (it = c.begin(); it != c.end(); ++it) {
        if ((*it) == this) {
            return i;
        }
        ++i;
    }
    assert(false);
    return 0;
}

void PathSegment::print(std::ostream &os) const {
    //   os << "seg stateId=" << std::dec << m_StateId << " ";

    PathFragmentList::const_iterator it;
    for (it = m_FragmentList.begin(); it != m_FragmentList.end(); ++it) {
        (*it).print(os);
        os << " ";
    }
    os << std::endl;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

PathBuilder::PathBuilder(LogParser *log) {
    m_Parser = log;

    m_connection = log->onEachItem.connect(sigc::mem_fun(*this, &PathBuilder::onItem));

    m_Root = new PathSegment(NULL, 0, 0);
    m_CurrentSegment = m_Root;
    m_Leaves[0].push_back(m_CurrentSegment);
}

PathBuilder::~PathBuilder() {
    m_connection.disconnect();

    StateToSegments::iterator it;

    for (it = m_Leaves.begin(); it != m_Leaves.end(); ++it) {
        PathSegmentList &psl = (*it).second;
        PathSegmentList::iterator pslit;
        for (pslit = psl.begin(); pslit != psl.end(); ++pslit) {
            PathSegment *ps = *pslit;
            delete ps;
        }
    }
}

void PathBuilder::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {
    assert(m_CurrentSegment);
#ifdef DEBUG_PB
    std::cout << "PB: ID=" << (unsigned) hdr.stateId << " T=" << (unsigned) hdr.type << std::endl;
#endif

    if (hdr.stateId != m_CurrentSegment->getStateId()) {
        // Lookup the current state
        StateToSegments::iterator it = m_Leaves.find(hdr.stateId);

        // There must have been a fork that generated the state
        if (it == m_Leaves.end()) {
            std::cout << "Encountered a state id " << (int) hdr.stateId << " that was not forked before "
                      << (int) m_CurrentSegment->getStateId() << std::endl;
            assert(false);
        }

        // A new segment must have been created when the state was forked
        assert((*it).second.size() > 0);

        // Retrieve the latest segment to append new items to it.
        m_CurrentSegment = (*it).second.back();

#ifdef DEBUG_PB
        std::cout << "Switching to new state in the trace - parent=" << m_CurrentSegment->getParent()->getStateId()
                  << std::endl;
#endif

        // Check that the segment really belongs to us
        assert(m_CurrentSegment->getStateId() == hdr.stateId);

        // Since we have just switched to a new state, we must start a new fragment
        m_CurrentSegment->appendFragment(PathFragment(traceIndex, traceIndex));

        // m_CurrentSegment->print(std::cout);
    }

    ///////////////////////////
    assert(m_CurrentSegment->getStateId() == hdr.stateId);

    // Extend the current segment with a fragment
    // Note that forks are the last items in each fragment
    if (!m_CurrentSegment->hasFragments()) {
#ifdef DEBUG_PB
        std::cout << "Creating new fragment for segment " << m_CurrentSegment->getStateId() << std::endl;
#endif
        m_CurrentSegment->appendFragment(PathFragment(traceIndex, traceIndex));
    } else {
        m_CurrentSegment->expandLastFragment(traceIndex);
    }

#ifdef DEBUG_PB
    m_CurrentSegment->print(std::cout);
#endif

    ///////////////////////////
    if (hdr.type == s2e::plugins::TRACE_FORK) {
        s2e::plugins::ExecutionTraceFork *f = (s2e::plugins::ExecutionTraceFork *) item;
        // assert(f->stateCount == 2);
        for (unsigned i = 0; i < f->stateCount; ++i) {
            std::cout << "Forking " << hdr.stateId << " to " << f->children[i] << std::endl;
            PathSegment *newSeg = new PathSegment(m_CurrentSegment, f->children[i], f->pc);
            m_Leaves[f->children[i]].push_back(newSeg);
        }

        for (unsigned i = 0; i < f->stateCount; ++i) {
            if (m_CurrentSegment->getStateId() == f->children[i]) {
                m_CurrentSegment = m_CurrentSegment->getChildren()[i];
                break;
            }
        }
    }
}

void PathBuilder::enumeratePaths(ExecutionPaths &paths) {
    ExecutionPath currentPath;
    std::stack<PathSegment *> s;

    s.push(m_Root);

    while (s.size() > 0) {
        PathSegment *curSeg = s.top();
        s.pop();

#ifdef DEBUG_PB
        std::cout << "Poping " << curSeg->getStateId() << std::endl;
#endif

        const PathSegmentList &children = curSeg->getChildren();
        PathSegmentList::const_iterator it;

        assert(children.size() == 0 || children.size() == 2);

        if (children.size() > 0) {
            for (it = children.begin(); it != children.end(); ++it) {
#ifdef DEBUG_PB
                std::cout << "Pushing children " << (*it)->getStateId() << std::endl;
#endif
                s.push(*it);
            }
        } else {
#ifdef DEBUG_PB
            std::cout << ">Building path" << std::endl;
#endif
            // We have finished traversing one path, build it.
            paths.push_back(ExecutionPath());
            ExecutionPath &curPath = paths.back();

            // curSeg = curSeg->getParent();
            while (curSeg->getParent() != 0) {
                curPath.push_back(curSeg->getIndexInParent());
                curSeg = curSeg->getParent();
            }
        }
    }
}

void PathBuilder::printPath(const ExecutionPath &p, std::ostream &os) {
    ExecutionPath::const_reverse_iterator it;
    for (it = p.rbegin(); it != p.rend(); ++it) {
        os << (*it) << " ";
    }
    os << std::endl;
}

void PathBuilder::printPaths(const ExecutionPaths &p, std::ostream &os) {
    ExecutionPaths::const_iterator it;
    for (it = p.begin(); it != p.end(); ++it) {
        printPath(*it, os);
    }
}

void PathBuilder::processSegment(PathSegment *seg) {
    const PathFragmentList &fra = seg->getFragmentList();
    PathFragmentList::const_iterator it;
    s2e::plugins::ExecutionTraceItemHeader hdr;
    uint8_t *data;

#ifdef DEBUG_PB
    std::cout << std::dec << "Processing segment of state " << seg->getStateId() << " ";
    const PathSegmentList &ps = seg->getChildren();
    PathSegmentList::const_iterator pit;
    for (pit = ps.begin(); pit != ps.end(); ++pit) {
        std::cout << "child=" << (*pit)->getStateId() << " ";
    }
    std::cout << std::endl;
#endif

    for (it = fra.begin(); it != fra.end(); ++it) {
        const PathFragment &f = (*it);
#ifdef DEBUG_PB
        std::cout << std::dec << "sid=" << seg->getStateId() << " frag(" << f.startIndex << "," << f.endIndex << ")"
                  << std::endl;
#endif
        for (uint32_t s = f.startIndex; s <= f.endIndex; ++s) {
            if (!m_Parser->getItem(s, hdr, (void **) &data)) {
                assert(false && "Trace is broken");
            }
#ifdef DEBUG_PB
// std::cout << "T: " << (unsigned)hdr.type << std::endl;
#endif
            assert(hdr.stateId == seg->getStateId());
            processItem(s, hdr, data);
        }
    }
}

bool PathBuilder::processPath(uint32_t pathId) {
    resetTree();

    StateToSegments::iterator it;
    it = m_Leaves.find(pathId);
    if (it == m_Leaves.end()) {
        return false;
    }

    std::vector<PathSegment *> segments;
    PathSegment *seg = (*it).second.back();
    while (seg) {
        segments.push_back(seg);
        seg = seg->getParent();
    }

    for (int i = segments.size() - 1; i >= 0; --i) {
        m_CurrentSegment = segments[i];

        if (m_CurrentSegment->getParent()) {
            // Copy the trace analyzer's state from the parent
            // to the current segment.
            assert(m_CurrentSegment->getStateMap().empty());
            PathSegmentStateMap &pm = m_CurrentSegment->getParent()->getStateMap();
            PathSegmentStateMap &m = m_CurrentSegment->getStateMap();

            PathSegmentStateMap::iterator it;
            for (it = pm.begin(); it != pm.end(); ++it) {
                m[(*it).first] = (*it).second->clone();
            }
        }

        processSegment(segments[i]);
    }

    return true;
}

// Discards all segment-local information kept by trace processors.
void PathBuilder::resetTree() {
    StateToSegments::iterator it;

    for (it = m_Leaves.begin(); it != m_Leaves.end(); ++it) {
        PathSegmentList &psl = (*it).second;
        PathSegmentList::iterator pslit;
        for (pslit = psl.begin(); pslit != psl.end(); ++pslit) {
            PathSegment *ps = *pslit;
            ps->deleteState();
        }
    }
}

void PathBuilder::processTree() {
    ExecutionPath currentPath;
    std::stack<PathSegment *> s;

    s.push(m_Root);

    while (s.size() > 0) {
        PathSegment *curSeg = s.top();
        m_CurrentSegment = curSeg;
        s.pop();

        if (curSeg->getParent()) {
            // Copy the trace analyzer's state from the parent
            // to the current segment. This assumes that we process segments in
            // depth-first order.
            assert(curSeg->getStateMap().empty());
            PathSegmentStateMap &pm = curSeg->getParent()->getStateMap();
            PathSegmentStateMap &m = curSeg->getStateMap();

            PathSegmentStateMap::iterator it;
            for (it = pm.begin(); it != pm.end(); ++it) {
                m[(*it).first] = (*it).second->clone();
            }
        }

        processSegment(curSeg);

        const PathSegmentList &children = curSeg->getChildren();
        PathSegmentList::const_iterator it;

        // assert(children.size() == 0 || children.size() == 2);

        if (children.size() > 0) {
            for (it = children.begin(); it != children.end(); ++it) {
                s.push(*it);
            }
        }
    }
}

ItemProcessorState *PathBuilder::getState(void *processor, ItemProcessorStateFactory f) {
    PathSegmentStateMap &m = m_CurrentSegment->getStateMap();
    PathSegmentStateMap::iterator it = m.find(processor);
    if (it != m.end()) {
        return (*it).second;
    }

    ItemProcessorState *s = f();
    m[processor] = s;
    return s;
}

ItemProcessorState *PathBuilder::getState(void *processor, uint32_t pathId) {
    StateToSegments::iterator it;
    it = m_Leaves.find(pathId);
    if (it == m_Leaves.end()) {
        return NULL;
    }

    PathSegment *seg = (*it).second.back();
    PathSegmentStateMap &m = seg->getStateMap();
    PathSegmentStateMap::iterator sit = m.find(processor);
    if (sit == m.end()) {
        return NULL;
    }
    return (*sit).second;
}

void PathBuilder::getPaths(PathSet &s) {
    StateToSegments::iterator it;

    s.clear();
    for (it = m_Leaves.begin(); it != m_Leaves.end(); ++it) {
        s.insert((*it).first);
    }
}
}
