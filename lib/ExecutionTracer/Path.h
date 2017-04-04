///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_EXECTRACER_PATH_H

#define S2ETOOLS_EXECTRACER_PATH_H

#include <map>
#include <vector>

#include "LogParser.h"

namespace s2etools {

/**
 *  Represents a contiguous sequence of trace entries belonging to the same state.
 */
struct PathFragment {
    uint32_t startIndex, endIndex;
    PathFragment(uint32_t s, uint32_t e) {
        startIndex = s;
        endIndex = e;
    }

    void print(std::ostream &os) const {
        os << std::dec << "(" << startIndex << "," << endIndex << ")";
    }
};

/**
 *  Represents a sequence of fragments between to fork point
 */
typedef std::vector<PathFragment> PathFragmentList;

class PathSegment;
typedef std::vector<PathSegment *> PathSegmentList;
typedef std::map<void *, ItemProcessorState *> PathSegmentStateMap;

/**
 *  A path segment is a sequence of fragments terminated by a fork point
 */
class PathSegment {
private:
    PathSegment *m_Parent;
    uint32_t m_StateId;
    uint64_t m_ForkPc;

    PathFragmentList m_FragmentList;

    /** Pointers to the forked children */
    PathSegmentList m_Children;

    /** Holds the per-trace processor state */
    PathSegmentStateMap m_SegmentState;

public:
    PathSegment(PathSegment *parent, uint32_t stateId, uint64_t forkPc);
    uint32_t getStateId() const {
        return m_StateId;
    }

    ~PathSegment();

    void deleteState();

    void appendFragment(const PathFragment &f) {
        m_FragmentList.push_back(f);
    }

    void expandLastFragment(uint32_t newEnd) {
        assert(m_FragmentList.back().endIndex <= newEnd);
        m_FragmentList.back().endIndex = newEnd;
    }

    bool hasFragments() const {
        return m_FragmentList.size() > 0;
    }

    const PathFragmentList &getFragmentList() const {
        return m_FragmentList;
    }

    const PathSegmentList &getChildren() const {
        return m_Children;
    }

    PathSegmentStateMap &getStateMap() {
        return m_SegmentState;
    }

    unsigned getIndexInParent() const;

    PathSegment *getParent() const {
        return m_Parent;
    }

    void print(std::ostream &os) const;
};

typedef std::map<uint32_t, PathSegmentList> StateToSegments;

// Sequence of indexes in the children set
typedef std::vector<uint32_t> ExecutionPath;
typedef std::vector<ExecutionPath> ExecutionPaths;

class PathBuilder : public LogEvents {
private:
    PathSegment *m_Root;
    PathSegment *m_CurrentSegment;
    StateToSegments m_Leaves;
    LogParser *m_Parser;
    sigc::connection m_connection;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

    void processSegment(PathSegment *seg);

public:
    PathBuilder(LogParser *log);
    ~PathBuilder();

    // The paths are inverted!
    void enumeratePaths(ExecutionPaths &paths);

    static void printPath(const ExecutionPath &p, std::ostream &os);
    static void printPaths(const ExecutionPaths &p, std::ostream &os);

    bool processPath(uint32_t);
    void processTree();

    void resetTree();
    virtual ItemProcessorState *getState(void *processor, ItemProcessorStateFactory f);
    virtual ItemProcessorState *getState(void *processor, uint32_t pathId);
    virtual void getPaths(PathSet &s);
};
}

#endif
