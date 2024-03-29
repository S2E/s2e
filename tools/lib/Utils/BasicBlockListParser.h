///
/// Copyright (C) 2011-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
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

#ifndef S2ETOOLS_BBLP_H
#define S2ETOOLS_BBLP_H

#include <inttypes.h>
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
} // namespace s2etools

#endif
