///
/// Copyright (C) 2013-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2020, Cyberhaven
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

#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/LoopInfoImpl.h>

#include <llvm/Support/GenericDomTree.h>
#include <llvm/Support/GenericDomTreeConstruction.h>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/GraphWriter.h>
#include <llvm/Support/raw_ostream.h>

#include <sstream>
#include <stdio.h>

#include "CFG/BinaryCFG.h"
#include "CFG/Graph.h"
#include "lib/Utils/BinaryCFGReader.h"

using namespace llvm;

namespace {
cl::opt<std::string> McSemaCfg("mcsema-cfg", cl::desc("CFG in protobuf format"), cl::Optional);

cl::opt<std::string> CfgFile("cfg", cl::desc("Text file containing the cfg for each function"), cl::Optional);

cl::opt<std::string> BbFile("bbs", cl::desc("Text file containing the list of basic blocks"), cl::Optional);

cl::opt<std::string> LuaLoopsFile("lua-loops", cl::desc("File where to output the loop info in lua format"),
                                  cl::Optional);

cl::opt<std::string> LuaCfgFile("lua-cfg", cl::desc("File where to output the CFG info in lua format"), cl::Required);

cl::opt<std::string> LuaMergePoints("lua-merge", cl::desc("File where to output the merge point info in lua format"),
                                    cl::Optional);

cl::opt<std::string>
    ModuleId("moduleid",
             cl::desc("Module ID which the info belongs to (as defined by the ModuleExecutionDetector plugin)"),
             cl::Required);

cl::opt<bool> DebugWriteDot("debug-write-dot", cl::desc("Write a dot file in for each function"), cl::init(false));

cl::opt<std::string> DebugFunction("debug-function", cl::desc("Write a dot file in for each function"), cl::init(""),
                                   cl::Optional);

cl::opt<std::string> DebugOutputDir("debug-output", cl::desc("Path where to put debug files"), cl::init("/tmp"),
                                    cl::Optional);
} // namespace

namespace llvm {

///////////////////////////////////////////////////////////////////

typedef DomTreeNodeBase<BinaryBasicBlock> BinaryDomTreeNode;

template <> struct GraphTraits<BinaryDomTreeNode *> {
    typedef BinaryDomTreeNode NodeType;
    typedef NodeType *NodeRef;
    typedef BinaryDomTreeNode::iterator ChildIteratorType;

    static NodeRef getEntryNode(BinaryDomTreeNode *N) {
        return N;
    }

    static ChildIteratorType child_begin(NodeRef N) {
        return N->begin();
    }

    static ChildIteratorType child_end(NodeRef N) {
        return N->end();
    }

    typedef df_iterator<BinaryDomTreeNode *> nodes_iterator;

    static nodes_iterator nodes_begin(BinaryDomTreeNode *N) {
        return df_begin(getEntryNode(N));
    }

    static nodes_iterator nodes_end(BinaryDomTreeNode *N) {
        return df_end(getEntryNode(N));
    }
};

template <> struct GraphTraits<const BinaryDomTreeNode *> {
    typedef const BinaryDomTreeNode NodeType;
    typedef const NodeType *NodeRef;
    typedef BinaryDomTreeNode::const_iterator ChildIteratorType;

    static NodeRef getEntryNode(const BinaryDomTreeNode *N) {
        return N;
    }

    static ChildIteratorType child_begin(NodeRef N) {
        return N->begin();
    }

    static ChildIteratorType child_end(NodeRef N) {
        return N->end();
    }

    typedef df_iterator<const BinaryDomTreeNode *> nodes_iterator;

    static nodes_iterator nodes_begin(const BinaryDomTreeNode *N) {
        return df_begin(getEntryNode(N));
    }

    static nodes_iterator nodes_end(const BinaryDomTreeNode *N) {
        return df_end(getEntryNode(N));
    }
};

struct BinaryLoop : public LoopBase<BinaryBasicBlock, BinaryLoop> {
    explicit BinaryLoop(BinaryBasicBlock *BB) : LoopBase(BB) {
    }
};

typedef LoopInfoBase<BinaryBasicBlock, BinaryLoop> BinaryLoopInfo;

///////////////////////////////////////////////////////////////////

} // namespace llvm

template <typename T> static void EnumerateLoops(std::vector<BinaryLoop *> &loops, const T &loop) {
    BinaryLoopInfo::iterator it;
    for (it = loop.begin(); it != loop.end(); ++it) {
        loops.push_back(*it);
        EnumerateLoops(loops, **it);
    }
}

static void LuaGenerateBackEdges(raw_ostream &os, const BinaryFunction *f, const BinaryLoopInfo &loopInfo,
                                 unsigned &count) {
    if (loopInfo.empty()) {
        return;
    }

    uint64_t entry_pc = f->getEntryBlock()->getStartPc();

    os << "  -- Function " << hexval(entry_pc) << "\n";

    std::vector<BinaryLoop *> loops;
    EnumerateLoops(loops, loopInfo);

    std::vector<BinaryLoop *>::iterator it;

    for (it = loops.begin(); it != loops.end(); ++it) {
        BinaryLoop *loop = *it;
        BinaryBasicBlock *bb = loop->getLoopLatch();
        uint64_t end_pc = 0;
        uint64_t start_pc = 0;
        if (bb) {
            start_pc = bb->getStartPc();
            end_pc = bb->getEndPc();
        }

        BinaryBasicBlock *header = loop->getHeader();

        os << "  l" << count << " = {\n";
        os << "    header = " << hexval(header->getStartPc()) << ",\n";

        ////////////////////////////////////////
        os << "    backedges = {\n";

        for (BinaryBasicBlock::pred_iterator pit = header->pred_begin(); pit != header->pred_end(); ++pit) {
            if (loop->contains(*pit)) {
                os << "      {" << hexval((*pit)->getEndPc()) << ", " << hexval(header->getStartPc()) << "},\n";
            }
        }
        os << "    },\n";

        ////////////////////////////////////////
        os << "    exitedges = {\n";

        SmallVector<BinaryBasicBlock *, 4> ExitBlocks;
        loop->getExitBlocks(ExitBlocks);
        SmallVectorImpl<BinaryBasicBlock *>::const_iterator eit;

        for (eit = ExitBlocks.begin(); eit != ExitBlocks.end(); ++eit) {
            BinaryBasicBlock::pred_iterator pit = (*eit)->pred_begin();
            for (; pit != (*eit)->pred_end(); ++pit) {
                if (loop->contains(*pit)) {
                    os << "      {" << hexval((*pit)->getEndPc()) << ", " << hexval((*eit)->getStartPc()) << "},\n";
                }
            }
        }

        os << "    },\n";

        ////////////////////////////////////////
        os << "    exitblocks = {";

        // SmallVector<BinaryBasicBlock*, 4> ExitBlocks;
        // loop->getExitBlocks(ExitBlocks);
        // SmallVectorImpl<BinaryBasicBlock*>::const_iterator eit;

        for (eit = ExitBlocks.begin(); eit != ExitBlocks.end(); ++eit) {
            os << hexval((*eit)->getStartPc()) << ", ";
        }

        os << "},\n";
        ////////////////////////////////////////
        os << "    basicblocks = {";

        std::vector<BinaryBasicBlock *> BasicBlocks;
        BasicBlocks = loop->getBlocks();
        std::vector<BinaryBasicBlock *>::const_iterator bit;

        for (bit = BasicBlocks.begin(); bit != BasicBlocks.end(); ++bit) {
            os << hexval((*bit)->getStartPc()) << ", ";
        }

        os << "},\n";
        ////////////////////////////////////////
        os << "  },\n";

        ++count;
    }
}

void LuaGenerateCfg(const BinaryFunctions &functions) {
    std::error_code EC;
    raw_fd_ostream os(LuaCfgFile.c_str(), EC, llvm::sys::fs::F_None);

    if (EC) {
        llvm::errs() << "Could not open " << LuaCfgFile << " - " << EC.message() << "\n";
        exit(-1);
    }

    os << "pluginsConfig.ControlFlowGraph[\"" << ModuleId << "\"] = {\n";

    /////////////////////////////
    os << "    functions = {\n";

    BinaryFunctions::const_iterator it;
    for (it = functions.begin(); it != functions.end(); ++it) {
        BinaryFunction *f = *it;
        os << "          ";
        os << "{";
        os << "pc=" << hexval(f->getEntryBlock()->getStartPc()) << ", ";
        os << "name=\"" << f->getName() << "\"";
        os << "},\n";
    }

    os << "\n";
    os << "    },\n";
    /////////////////////////////
    os << "    basicblocks = {\n";

    for (it = functions.begin(); it != functions.end(); ++it) {
        BinaryFunction *f = *it;
        os << "        -- " << hexval(f->getEntryBlock()->getStartPc()) << "\n";
        BinaryFunction::const_iterator bbit;
        for (bbit = f->begin(); bbit != f->end(); ++bbit) {
            const BinaryBasicBlock *bb = *bbit;
            os << "        {\n";
            os << "            start_pc = " << hexval(bb->getStartPc()) << ",\n";
            os << "            end_pc   = " << hexval(bb->getEndPc()) << ",\n";
            os << "            size     = " << hexval(bb->getSize()) << ",\n";

            if (bb->isCall()) {
                os << "            bbtype   = " << hexval(bb->getType()) << ",\n";
                os << "            call_target = " << hexval(bb->getTargetPc()) << ",\n";
            }

            BinaryBasicBlock::const_succ_iterator cit;

            if (bb->succ_begin() != bb->succ_end()) {
                os << "            successors = {";
                for (cit = bb->succ_begin(); cit != bb->succ_end(); ++cit) {
                    os << hexval((*cit)->getStartPc()) << ", ";
                }
                os << "},\n";
            }

            if (bb->pred_begin() != bb->pred_end()) {
                os << "            predecessors = {";
                for (cit = bb->pred_begin(); cit != bb->pred_end(); ++cit) {
                    os << hexval((*cit)->getStartPc()) << ", ";
                }
                os << "},\n";
            }
            os << "        },\n";
        }
    }

    os << "    }\n";

    os << "}\n";
    os.close();
}

template <bool IsPostDom> using BinaryDomTree = DominatorTreeBase<BinaryBasicBlock, IsPostDom>;

typedef llvm::DenseSet<const BinaryBasicBlock *> BinaryBasicBlocksSet;

template <bool IsPostDom>
static void GetChildren(BinaryDomTree<IsPostDom> &dom, BinaryBasicBlock *bb, BinaryBasicBlock *bb_end,
                        BinaryBasicBlocksSet &blocks) {
    auto node = dom.getNode(bb);

    blocks.insert(bb);

    for (auto it = node->begin(); it != node->end(); ++it) {
        if ((*it)->getBlock() != bb_end) {
            GetChildren(dom, (*it)->getBlock(), bb_end, blocks);
        }
    }
}

typedef std::pair<const BinaryBasicBlock *, const BinaryBasicBlock *> MergePair;
typedef std::set<MergePair> MergePoints;

static void LuaGenerateMergePoints(const MergePoints &mergePoints) {
    std::error_code EC;
    raw_fd_ostream os(LuaMergePoints.c_str(), EC, llvm::sys::fs::F_None);
    if (EC) {
        llvm::errs() << "Could not open " << LuaMergePoints << " - " << EC.message() << "\n";
        exit(-1);
    }

    os << "pluginsConfig.StaticStateMerger[\"" << ModuleId << "\"] = {\n";

    MergePoints::const_iterator it;
    for (it = mergePoints.begin(); it != mergePoints.end(); ++it) {
        const MergePair &p = (*it);
        os << "    {" << hexval(p.first->getStartPc()) << ", " << hexval(p.second->getStartPc()) << "},\n";
    }

    os << "}\n";
}

static void ComputeMergePoints(BinaryFunction *f, BinaryDomTree<false> &dom, BinaryDomTree<true> &postdom,
                               BinaryLoopInfo &loopInfo, MergePoints &mergePoints) {
    BinaryFunction::iterator it;
    BinaryBasicBlocksSet mergedBlocks;

    std::vector<BinaryLoop *> loops;
    EnumerateLoops(loops, loopInfo);

    BinaryBasicBlocksSet AllExitBlocks, JumpToHeader;
    for (unsigned i = 0; i < loops.size(); ++i) {
        BinaryBasicBlock::Children ExitBlocks;
        loops[i]->getExitBlocks(ExitBlocks);
        AllExitBlocks.insert(ExitBlocks.begin(), ExitBlocks.end());

        BinaryBasicBlock *loopHeader = loops[i]->getHeader();
        const std::vector<BinaryBasicBlock *> &loopBbs = loops[i]->getBlocks();
        for (unsigned j = 0; j < loopBbs.size(); ++j) {
            const BinaryBasicBlock *lbb = loopBbs[j];
            for (auto it = lbb->succ_begin(); it != lbb->succ_end(); ++it) {
                if (*it == loopHeader) {
                    JumpToHeader.insert(lbb);
                }
            }
        }
    }

    for (it = f->begin(); it != f->end(); ++it) {
        BinaryBasicBlock *bb = *it;

        if (bb->isCall() || bb->numSuccessors() < 2) {
            if (DebugWriteDot) {
                llvm::errs() << "ComputeMergePoints: " << hexval(bb->getStartPc())
                             << " not enough successors or call node\n";
            }
            continue;
        }

        if (loopInfo.isLoopHeader(bb)) {
            if (DebugWriteDot) {
                llvm::errs() << "ComputeMergePoints: " << hexval(bb->getStartPc()) << " is a loop header, skipping\n";
            }
            continue;
        }

        bool next = false;
        for (BinaryBasicBlock::succ_iterator it = bb->succ_begin(); it != bb->succ_end(); ++it) {
            if (AllExitBlocks.find(*it) != AllExitBlocks.end()) {
                if (DebugWriteDot) {
                    llvm::errs() << "ComputeMergePoints: " << hexval(bb->getStartPc())
                                 << " branches to an exit block\n";
                }
                next = true;
                break;
            }
        }
        if (next) {
            continue;
        }

        // Can't have recursive merge blocks for now
        if (mergedBlocks.find(bb) != mergedBlocks.end()) {
            if (DebugWriteDot) {
                llvm::errs() << "ComputeMergePoints: " << hexval(bb->getStartPc()) << " already in merge block\n";
            }
            continue;
        }

        if (!postdom.getNode(bb) || !postdom.getNode(bb)->getIDom()) {
            continue;
        }

        auto ipdom = postdom.getNode(bb)->getIDom()->getBlock();
        // llvm::errs() << "postdom for " << hexval(bb->getStartPc()) << ": " << hexval(ipdom->getStartPc()) << "\n";
        if (!ipdom) {
            continue;
        }

        if (!dom.getNode(ipdom)) {
            continue;
        }

        auto idom = dom.getNode(ipdom)->getIDom()->getBlock();
        if (!idom) {
            continue;
        }

        // llvm::errs() << "dom for " << hexval(ipdom->getStartPc()) << ": " << hexval(idom->getStartPc()) << "\n";

        if (idom != bb) {
            continue;
        }

        BinaryBasicBlock *mergeStart = bb;
        BinaryBasicBlock *mergeEnd = ipdom;

        // Get the set of bbs in between the merge markers
        llvm::DenseSet<const BinaryBasicBlock *> blocks;
        GetChildren(dom, mergeStart, mergeEnd, blocks);

        llvm::DenseSet<const BinaryBasicBlock *>::iterator it = blocks.begin();

        if (DebugWriteDot) {
            llvm::errs() << hexval(f->getEntryBlock()->getStartPc()) << ": checking " << hexval(bb->getStartPc())
                         << ", " << hexval(ipdom->getStartPc()) << "\n";
        }

        bool skip = false;
        for (it = blocks.begin(); it != blocks.end(); ++it) {
            if ((*it)->isCall()) {
                if (DebugWriteDot) {
                    llvm::errs() << hexval((*it)->getStartPc()) << " is a call\n";
                }
                skip = true;
                break;
            }
        }

        if (skip) {
            continue;
        }

        // Make sure that there are no back edges in the merged block
        llvm::DenseSet<const BinaryBasicBlock *>::iterator beit = JumpToHeader.begin();
        for (; beit != JumpToHeader.end(); ++beit) {
            if (blocks.find(*beit) != blocks.end()) {
                skip = true;
                if (DebugWriteDot) {
                    llvm::errs() << hexval((*beit)->getStartPc()) << " has a backedge \n";
                }
                break;
            }
        }

        if (skip) {
            continue;
        }

        if (DebugWriteDot) {
            llvm::errs() << hexval(f->getEntryBlock()->getStartPc()) << ": " << hexval(bb->getStartPc()) << ", "
                         << hexval(ipdom->getStartPc()) << " is a mergeable tree\n";
        }

        mergePoints.insert(MergePair(bb, ipdom));
        mergedBlocks.insert(blocks.begin(), blocks.end());

        // TODO: handle cases when a block has both a merge end and a merge start
        // The following line prevents this from happening (misses merging opportunities)
        mergedBlocks.insert(mergeEnd);
    }
}

static void verifyFunctions(BinaryFunctions &functions) {
    for (BinaryFunctions::const_iterator fit = functions.begin(); fit != functions.end(); ++fit) {
        const BinaryFunction *f = *fit;
        // llvm::errs() << "Function at " << hexval(f->getEntryBlock()->getStartPc())
        //             << " has " << f->m_nodes.size() << " basic blocks\n";

        for (BinaryFunction::iterator bbit = f->begin(); bbit != f->end(); ++bbit) {
            const BinaryBasicBlock *bb = *bbit;
            if (!bb->getSize()) {
                llvm::errs() << "Function at " << hexval(f->getEntryBlock()->getStartPc()) << " has zero-sized bb "
                             << hexval(bb->getStartPc()) << "\n";
                exit(-1);
            }
        }
    }
}

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, (char **) argv, " analysis");

    BinaryBasicBlocks bbs;
    BinaryFunctions functions;

    if (McSemaCfg.size() > 0) {
        bool ret = ParseMcSemaCfgFile(McSemaCfg, bbs, functions);
        if (!ret) {
            llvm::errs() << "Could not parse mcsema cfg file\n";
            return -1;
        }
    } else {
        if (!ParseBBInfoFile(BbFile, bbs)) {
            llvm::errs() << "Count not parse bb info file\n";
            return -2;
        }

        if (!ParseCfgFile(CfgFile, bbs, functions)) {
            llvm::errs() << "Count not parse cfg file\n";
            return -3;
        }
    }

    verifyFunctions(functions);

    LuaGenerateCfg(functions);

    if (LuaMergePoints.size() && !LuaLoopsFile.size()) {
        llvm::errs() << "LuaLoopsFile is required for LuaMergePoints\n";
        exit(-1);
    }

    if (LuaLoopsFile.size()) {
        std::error_code EC;
        raw_fd_ostream ofs(LuaLoopsFile.c_str(), EC, llvm::sys::fs::F_None);
        if (EC) {
            llvm::errs() << "Could not open " << LuaLoopsFile << " - " << EC.message() << "\n";
            exit(-1);
        }

        ofs << "pluginsConfig.LoopDetector[\"" << ModuleId << "\"] = {\n";

        BinaryFunctions::const_iterator it;

        uint64_t func_addr = 0;
        if (DebugFunction.size() > 0) {
            func_addr = strtol(DebugFunction.c_str(), NULL, 0);
        }

        unsigned count = 0;
        MergePoints mergePoints;

        for (it = functions.begin(); it != functions.end(); ++it) {
            BinaryFunction *f = *it;

            if (func_addr && f->getEntryBlock()->getStartPc() != func_addr) {
                continue;
            }

            if (DebugWriteDot) {
                std::stringstream fss;
                fss << DebugOutputDir << "/fcn" << std::hex << f->getEntryBlock()->getStartPc();
                llvm::errs() << "Writing " << fss.str() << "...\n";
                llvm::raw_fd_ostream dotf(fss.str(), EC, llvm::sys::fs::F_None);
                BinaryFunctionGT wrappedF(f);
                WriteGraph(dotf, &wrappedF);

                dotf.close();
                std::stringstream dot2png;
                dot2png << "dot -Tpng " << fss.str() << " > " << fss.str() << ".png";
                system(dot2png.str().c_str());
            }

            BinaryFunctionGT wrappedF(f);

            BinaryDomTree<false> dom;
            dom.recalculate(wrappedF);

            BinaryDomTree<true> postdom;
            postdom.recalculate(wrappedF);

            BinaryLoopInfo loopInfo;
            loopInfo.analyze(dom);

            if (DebugWriteDot && func_addr) {
                dom.print(errs());
                postdom.print(errs());
                loopInfo.print(errs());
            }

            ComputeMergePoints(f, dom, postdom, loopInfo, mergePoints);
            LuaGenerateBackEdges(ofs, f, loopInfo, count);
        }

        ofs << "}\n";

        if (LuaMergePoints.size()) {
            LuaGenerateMergePoints(mergePoints);
        }
    }

    return 0;
}
