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

#include <fstream>
#include <sstream>
#include <stdio.h>

#include <llvm/Support/raw_ostream.h>

#include "cfg.pb.h"

#include "BinaryCFGReader.h"

namespace llvm {

static bool IsTerminatorInstruction(const std::string &bytes) {
    if (bytes.empty()) {
        return false;
    }

    const uint8_t TERMINATOR_OPCODES[9] = {
        0xF4, // HLT
        0xFF, // CALL
        0xE8, // CALL
        0x9A, // CALL
        0xCC, // INT
        0xCD, // INT
        0xCE, // INT
        0xF2, // REPNE
        0xF3  // REPE
    };

    for (auto const &opcode : TERMINATOR_OPCODES) {
        if ((uint8_t) bytes[0] == opcode) {
            return true;
        }
    }

    return false;
}

bool ParseMcSemaCfgFile(const std::string &file, BinaryBasicBlocks &bbs, BinaryFunctions &functions) {
    std::ifstream input(file);
    mcsema::Module module;

    if (!module.ParseFromIstream(&input)) {
        llvm::errs() << "Parsing McSema module failed\n";

        return false;
    }

    for (const mcsema::Function &f : module.internal_funcs()) {
        std::stringstream ss;

        if (!f.name().empty()) {
            ss << f.name();
        } else {
            ss << "sub_" << hexval(f.entry_address());
        }

        BinaryFunction *bf = new BinaryFunction(ss.str());
        functions.insert(bf);

        for (const mcsema::Block &b : f.blocks()) {
            if (b.insts_size() == 0) {
                continue;
            }

            auto iit_begin = b.insts().begin();
            auto iit_end = b.insts().end();
            auto iit = iit_begin;

            do {
                // Set default base address in case block turns out to be empty
                int64_t base_addr = b.base_address();
                int64_t last_addr;
                int64_t size = 0;

                if (iit != iit_end) {
                    base_addr = (*iit).inst_addr();
                }

                while (iit != iit_end) {
                    const mcsema::Instruction &i = *iit;
                    last_addr = i.inst_addr();
                    size += i.inst_len();
                    ++iit;

                    // The blocks returned by mcsema might not be properly
                    // terminated on instructions that change control flow
                    // such as calls, interrupts, etc. Split the blocks here.
                    if (IsTerminatorInstruction(i.inst_bytes())) {
                        break;
                    }
                }

                assert(base_addr <= last_addr);
                BinaryBasicBlock *binaryBb = new BinaryBasicBlock(base_addr, last_addr, size);
                bbs.insert(binaryBb);

                if (binaryBb->getStartPc() == (uint64_t) f.entry_address()) {
                    bf->setEntryBlock(binaryBb);
                }

                bf->add(binaryBb);
            } while (iit != iit_end);
        }

        // Go again through the list to update the successors
        for (const mcsema::Block &b : f.blocks()) {
            if (b.insts_size() == 0) {
                continue;
            }

            BinaryBasicBlock *binaryBb = bbs.find(b.base_address());
            assert(binaryBb);

            for (uint64_t follow : b.block_follows()) {
                BinaryBasicBlock *bb = bbs.find(follow);
                if (!bb) {
                    llvm::errs() << "Block " << hexval(b.base_address()) << " has incorrect follower " << hexval(follow)
                                 << "\n";
                    continue;
                }

                binaryBb->addSucc(bb);
                bb->addPred(binaryBb);
            }
        }
    }
    return true;
}

bool ParseBBInfoFile(const std::string &file, BinaryBasicBlocks &bbs) {
    const unsigned MAX_LINE = 512;
    char line[MAX_LINE];

    FILE *fp = fopen(file.c_str(), "r");
    if (!fp) {
        llvm::errs() << "Could not open " << file << "\n";
        return false;
    }

    while (fgets(line, MAX_LINE, fp)) {
        std::istringstream ss(line);
        std::string start, end, size, type_str, target_str;
        ss >> start >> end >> size >> type_str >> target_str;

        if (type_str == "c") {
            // Insert a call block
            bbs.insert(new BinaryBasicBlock(strtol(start.c_str(), NULL, 0), strtol(end.c_str(), NULL, 0),
                                            strtol(size.c_str(), NULL, 0), strtol(target_str.c_str(), NULL, 0)));
        } else {
            // Insert a normal block
            bbs.insert(new BinaryBasicBlock(strtol(start.c_str(), NULL, 0), strtol(end.c_str(), NULL, 0),
                                            strtol(size.c_str(), NULL, 0)));
        }
    }

    fclose(fp);
    return true;
}

bool ParseCfgFile(const std::string &file, BinaryBasicBlocks &bbs, BinaryFunctions &functions) {
    const unsigned MAX_LINE = 512;
    char line[MAX_LINE];

    FILE *fp = fopen(file.c_str(), "r");
    if (!fp) {
        llvm::errs() << "Could not open " << file << "\n";
        return false;
    }

    BinaryFunction *currentFunction = NULL;

    while (fgets(line, MAX_LINE, fp)) {
        std::istringstream ss(line);

        if (strstr(line, "function")) {
            std::string dummy, address_str, function_name;
            uint64_t address;
            ss >> dummy >> address_str >> function_name;

            if (function_name.size() == 0) {
                function_name = "<unknown>";
            }

            address = strtol(address_str.c_str(), NULL, 0);

            BinaryBasicBlock *bb = bbs.find(address);
            assert(bb && "Could not find entry point basic block");

            currentFunction = new BinaryFunction(function_name, bb);
            functions.insert(currentFunction);
        } else {
            std::string bb_str;
            uint64_t bb_addr;

            ss >> bb_str;
            bb_addr = strtol(bb_str.c_str(), NULL, 0);
            if (!bb_addr) {
                continue;
            }

            BinaryBasicBlock *bb = bbs.find(bb_addr);
            if (!bb) {
                llvm::errs() << "Warning: bb " << hexval(bb_addr) << " is undefined\n";
                continue;
            }

            BinaryBasicBlock::Children succs;
            while (!ss.eof()) {
                std::string edge_str;
                uint64_t edge_addr = 0;
                ss >> edge_str;
                edge_addr = strtol(edge_str.c_str(), NULL, 0);
                if (!edge_addr) {
                    continue;
                }

                BinaryBasicBlock *edge = bbs.find(edge_addr);
                if (edge) {
                    succs.push_back(edge);
                }
            }

            currentFunction->add(bb, succs);
        }
    }

    fclose(fp);
    return true;
}

} // namespace llvm
