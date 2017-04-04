///
/// Copyright (C) 2011-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_BBLP_H
#define S2ETOOLS_BBLP_H

#include <set>
#include <string>

namespace s2etools {

struct BasicBlock {
    uint64_t timeStamp;
    uint64_t start, size;
    std::string function;

    bool operator()(const BasicBlock &b1, const BasicBlock &b2) const {
        return b1.start + b1.size <= b2.start;
    }

    BasicBlock(uint64_t start, uint64_t size) {
        this->start = start;
        this->size = size;
        timeStamp = 0;
    }

    BasicBlock() {
        timeStamp = 0;
        start = size = 0;
    }

    struct SortByTime {

        bool operator()(const BasicBlock &b1, const BasicBlock &b2) const {
            if (b1.timeStamp < b2.timeStamp) {
                return true;
            }
            return b1.start + b1.size <= b2.start;
        }
    };
};

class BasicBlockListParser {
public:
    typedef std::set<BasicBlock, BasicBlock> BasicBlocks;

    static bool parseListing(std::string &listing, BasicBlocks &blocks);
};
}

#endif
