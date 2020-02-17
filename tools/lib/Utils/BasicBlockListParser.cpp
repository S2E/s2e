///
/// Copyright (C) 2011-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2017, Cyberhaven
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

#define __STDC_FORMAT_MACROS 1

#include "BasicBlockListParser.h"
#include <fstream>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <stdio.h>

namespace s2etools {

bool BasicBlockListParser::parseListing(std::string &listingFile, BasicBlocks &blocks) {
    std::filebuf file;
    if (!file.open(listingFile.c_str(), std::ios::in)) {
        return false;
    }

    std::istream is(&file);

    char line[1024];
    bool hasErrors = false;
    while (is.getline(line, sizeof(line))) {
        // Grab the start and the end
        uint64_t start, end;
        sscanf(line, "0x%" PRIx64 " 0x%" PRIx64 "", &start, &end);

        // Grab the function name
        std::string fcnName = line;
        fcnName.erase(fcnName.find_last_not_of(" \n\r\t") + 1);
        fcnName.erase(0, fcnName.find_last_of(" \t") + 1);

        BasicBlock bb(start, end - start + 1);
        BasicBlocks::iterator fit = blocks.find(bb);
        if (fit != blocks.end()) {
            std::cerr << "BasicBlockListParser: bb start=0x" << std::hex << bb.start << " size=0x" << bb.size
                      << " overlaps an existing block"
                      << " start:" << (*fit).start << std::endl;
            hasErrors = true;
            continue;
        }

        bb.function = fcnName;

        blocks.insert(bb);
    }

    return !hasErrors;
}
} // namespace s2etools
