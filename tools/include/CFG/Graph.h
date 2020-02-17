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

#ifndef S2E_TOOLS_GRAPH_H
#define S2E_TOOLS_GRAPH_H

#include <vector>

#include <llvm/ADT/GraphTraits.h>
#include <llvm/Support/DOTGraphTraits.h>

#include "BinaryCFG.h"

namespace llvm {

///
/// \brief Specialized BinaryFunction for use by the \c GraphTraits struct.
///
/// The \c GraphTraits \c nodes_iterator does not play nicely with \c std::set
/// (which is what \c BinaryFunction uses internally), so the \c set gets
/// transformed into a \c vector for use by the \c GraphTraits struct.
///
class BinaryFunctionGT {
public:
    typedef std::vector<BinaryBasicBlock *> BinaryBasicBlocks;

    // Binary function iterators
    typedef BinaryBasicBlocks::iterator iterator;
    typedef BinaryBasicBlocks::const_iterator const_iterator;

private:
    /// A vector of binary basic blocks to iterate over.
    mutable BinaryBasicBlocks BBs;

    /// Wrapped binary function.
    const BinaryFunction *F;

    void updateBasicBlocks() const {
        BBs.clear();

        for (auto it = F->begin(); it != F->end(); ++it) {
            BBs.push_back(*it);
        }
    }

public:
    /// Wrap a binary function.
    BinaryFunctionGT(const BinaryFunction *BF) : F(BF) {
    }

    BinaryBasicBlock *getEntryBlock() const {
        return F->getEntryBlock();
    }

    std::string getName() const {
        return F->getName();
    }

    unsigned size() const {
        return F->size();
    }

    iterator begin() {
        updateBasicBlocks();

        return BBs.begin();
    }

    iterator end() {
        updateBasicBlocks();

        return BBs.end();
    }

    const_iterator begin() const {
        updateBasicBlocks();

        return BBs.begin();
    }

    const_iterator end() const {
        updateBasicBlocks();

        return BBs.end();
    }
};

// Provide specializations of GraphTraits to be able to treat a BinaryFunction
// as a graph of BinaryBasicBlocks.

template <> struct GraphTraits<BinaryBasicBlock *> {
    typedef BinaryBasicBlock NodeType;
    typedef NodeType *NodeRef;
    typedef BinaryBasicBlock::succ_iterator ChildIteratorType;

    static NodeRef getEntryNode(NodeRef BB) {
        return BB;
    }

    static inline ChildIteratorType child_begin(NodeRef BB) {
        return BB->succ_begin();
    }

    static inline ChildIteratorType child_end(NodeRef BB) {
        return BB->succ_end();
    }
};

template <> struct GraphTraits<const BinaryBasicBlock *> {
    typedef const BinaryBasicBlock NodeType;
    typedef const NodeType *NodeRef;
    typedef BinaryBasicBlock::const_succ_iterator ChildIteratorType;

    static NodeRef getEntryNode(NodeRef BB) {
        return BB;
    }

    static inline ChildIteratorType child_begin(NodeRef BB) {
        return BB->succ_begin();
    }

    static inline ChildIteratorType child_end(NodeRef BB) {
        return BB->succ_end();
    }
};

// Provide specializations of GraphTraits to be able to treat a BinaryFunction
// as a graph of BinaryBasicBlocks and to walk it in inverse order. Inverse
// order for a function is considered to be when traversing the predecessor
// edges of a BinaryBasicBlock instead of the successor edges.

template <> struct GraphTraits<Inverse<BinaryBasicBlock *>> {
    typedef BinaryBasicBlock NodeType;
    typedef NodeType *NodeRef;
    typedef BinaryBasicBlock::pred_iterator ChildIteratorType;

    static inline ChildIteratorType child_begin(NodeRef BB) {
        return BB->pred_begin();
    }

    static inline ChildIteratorType child_end(NodeRef BB) {
        return BB->pred_end();
    }
};

template <> struct GraphTraits<Inverse<const BinaryBasicBlock *>> {
    typedef const BinaryBasicBlock NodeType;
    typedef const NodeType *NodeRef;
    typedef BinaryBasicBlock::const_pred_iterator ChildIteratorType;

    static inline ChildIteratorType child_begin(NodeRef BB) {
        return BB->pred_begin();
    }

    static inline ChildIteratorType child_end(NodeRef BB) {
        return BB->pred_end();
    }
};

// Provide specializations of GraphTraits to be able to treat a binary function
// as a graph of binary basic block... these are the same as the binary basic
// block iterators, except that the root node is implicitly the first node of
// the function.

template <> struct GraphTraits<BinaryFunctionGT *> : public GraphTraits<BinaryBasicBlock *> {
    static NodeRef getEntryNode(BinaryFunctionGT *F) {
        return F->getEntryBlock();
    }

    typedef BinaryFunctionGT::iterator nodes_iterator;

    static nodes_iterator nodes_begin(BinaryFunctionGT *F) {
        return F->begin();
    }

    static nodes_iterator nodes_end(BinaryFunctionGT *F) {
        return F->end();
    }

    static unsigned size(BinaryFunctionGT *F) {
        return F->size();
    }
};

template <> struct GraphTraits<const BinaryFunctionGT *> : public GraphTraits<const BinaryBasicBlock *> {
    static NodeRef getEntryNode(const BinaryFunctionGT *F) {
        return F->getEntryBlock();
    }

    typedef BinaryFunctionGT::const_iterator nodes_iterator;

    static nodes_iterator nodes_begin(const BinaryFunctionGT *F) {
        return F->begin();
    }

    static nodes_iterator nodes_end(const BinaryFunctionGT *F) {
        return F->end();
    }

    static unsigned size(const BinaryFunctionGT *F) {
        return F->size();
    }
};

// Specialized struct to convert a binary function to a DOT graph.
template <> struct DOTGraphTraits<BinaryFunctionGT *> : public DefaultDOTGraphTraits {
    DOTGraphTraits(bool simple = false) : DefaultDOTGraphTraits(simple) {
    }

    static std::string getGraphName(BinaryFunctionGT *F) {
        return F->getName();
    }

    std::string getNodeLabel(BinaryBasicBlock *BB, BinaryFunctionGT *F) {
        std::stringstream SS;
        SS << std::hex << BB->getStartPc();

        return SS.str();
    }

    static std::string getNodeAttributes(BinaryBasicBlock *BB, BinaryFunctionGT *F) {
        if (BB->isCall()) {
            return "color=red";
        } else {
            return "";
        }
    }
};

} // namespace llvm

#endif
