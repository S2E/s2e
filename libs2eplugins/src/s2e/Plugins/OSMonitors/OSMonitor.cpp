///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
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

#include <s2e/cpu.h>

#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "OSMonitor.h"

using namespace klee;

namespace s2e {
namespace plugins {

/// \brief Dump userspace memory pages
///
/// This function will print contents of all userspace pages.
/// Symbolic bytes will be marked as *SS* in hex output and printed separately.
///
/// Output format is similar to *hexdump -C*.
///
/// \param state current state
///
void OSMonitor::dumpUserspaceMemory(S2EExecutionState *state, std::ostream &ss) {
    const int columns = 2;
    const int columnWidth = 8;

    static_assert(columns >= 1, "Invalid option");
    static_assert(columnWidth >= 1, "Invalid option");
    static_assert(TARGET_PAGE_SIZE % (columns * columnWidth) == 0, "Invalid option");

    for (uint64_t virtAddr = 0; !isKernelAddress(virtAddr); virtAddr += TARGET_PAGE_SIZE) {
        s2e_assert(state, virtAddr <= UINT64_MAX - TARGET_PAGE_SIZE, "Address overflow");

        // TODO: parse pagedir manually to find mapped pages faster
        uint64_t hostAddr = state->mem()->getHostAddress(virtAddr);
        if ((int) hostAddr == -1) { // page is not mapped
            continue;
        }

        std::ostringstream concreteBytes;
        std::ostringstream symbolicBytes;

        for (int line = 0; line < TARGET_PAGE_SIZE / (columns * columnWidth); line++) {
            int lineOffset = line * columns * columnWidth;

            std::ostringstream hex;
            std::ostringstream ascii;
            for (int col = 0; col < columns; col++) {
                for (int n = 0; n < columnWidth; n++) {
                    int byteOffset = lineOffset + col * columnWidth + n;

                    ref<Expr> e = state->mem()->read(hostAddr + byteOffset, Expr::Int8, HostAddress);

                    if (e && isa<ConstantExpr>(e)) {
                        uint8_t v = dyn_cast<ConstantExpr>(e)->getZExtValue();
                        hex << " " << hexval(v, 2, false);
                        ascii << (isprint(v) ? (char) v : '.');
                    } else {
                        symbolicBytes << hexval(virtAddr + byteOffset, 8, false) << "  " << e << "\n";
                        hex << " SS";
                        ascii << '.';
                    }
                }

                hex << " ";
            }

            concreteBytes << hexval(virtAddr + lineOffset, 8, false) << " " << hex.str() << " |" << ascii.str()
                          << "|\n";
        }

        ss << "Contents of page " << hexval(virtAddr) << "\n" << concreteBytes.str() << symbolicBytes.str();
    }
}
} // namespace plugins
} // namespace s2e
