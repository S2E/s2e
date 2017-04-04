///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
