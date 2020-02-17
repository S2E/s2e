///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
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

#ifndef S2E_TOOLS_BINARY_CFG_READER_H
#define S2E_TOOLS_BINARY_CFG_READER_H

#include "CFG/BinaryCFG.h"

namespace llvm {

///
/// \brief Parse a CFG file produced by Trail of Bits' McSema tool.
///
/// \param file Path to the McSema CFG file to read
/// \param basicBlocks An ordered set of basic blocks read from the input file
/// \param functions An unordered set of functions read from the input file
/// \return \c true on success, \c false on failure
///
bool ParseMcSemaCfgFile(const std::string &file, BinaryBasicBlocks &basicBlocks, BinaryFunctions &functions);

///
/// \brief Parse a basic block information file produced by the S2E analysis
/// tool.
///
/// \param file Path to the basic block information file to read
/// \param basicBlocks An ordered set of basic blocks read from the input file
/// \t return \c true on success, \c false on failure
///
bool ParseBBInfoFile(const std::string &file, BinaryBasicBlocks &basicBlocks);

///
/// \brief Parse a CFG file produced by the S2E analysis tool.
///
/// \param file path to the CFG file to read
/// \param basicBlocks An ordered set of basic blocks read from the input file
/// \param functions An unordered set of functions read from the input file
/// \return \c true on success, \c false on failure
bool ParseCfgFile(const std::string &file, BinaryBasicBlocks &basicBlocks, BinaryFunctions &functions);

} // namespace llvm

#endif
