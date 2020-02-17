///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
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

#include "CFG/BinaryCFG.h"

namespace llvm {

void BinaryBasicBlock::addSucc(BinaryBasicBlock *BB) {
    for (auto &it : successors) {
        if (it == BB) {
            return;
        }
    }
    successors.push_back(BB);
}

void BinaryBasicBlock::addPred(BinaryBasicBlock *BB) {
    for (auto &it : predecessors) {
        if (it == BB) {
            return;
        }
    }

    predecessors.push_back(BB);
}

uint64_t BinaryBasicBlock::getStartPc() const {
    return startPc;
}

uint64_t BinaryBasicBlock::getEndPc() const {
    return endPc;
}

unsigned BinaryBasicBlock::getSize() const {
    return size;
}

BinaryBasicBlock::Type BinaryBasicBlock::getType() const {
    return type;
}

bool BinaryBasicBlock::isCall() const {
    return type == BB_CALL;
}

uint64_t BinaryBasicBlock::getTargetPc() const {
    return targetPc;
}

void BinaryBasicBlock::printAsOperand(raw_ostream &OS, bool printType) const {
    OS << "BB(" << hexval(startPc) << "," << hexval(endPc) << ")";
}

BinaryBasicBlock::succ_iterator BinaryBasicBlock::succ_begin() {
    return successors.begin();
}

BinaryBasicBlock::succ_iterator BinaryBasicBlock::succ_end() {
    return successors.end();
}

BinaryBasicBlock::const_succ_iterator BinaryBasicBlock::succ_begin() const {
    return successors.begin();
}

BinaryBasicBlock::const_succ_iterator BinaryBasicBlock::succ_end() const {
    return successors.end();
}

unsigned BinaryBasicBlock::numSuccessors() const {
    return successors.size();
}

unsigned BinaryBasicBlock::numPredecessors() const {
    return predecessors.size();
}

BinaryBasicBlock::pred_iterator BinaryBasicBlock::pred_begin() {
    return predecessors.begin();
}

BinaryBasicBlock::pred_iterator BinaryBasicBlock::pred_end() {
    return predecessors.end();
}

BinaryBasicBlock::const_pred_iterator BinaryBasicBlock::pred_begin() const {
    return predecessors.begin();
}

BinaryBasicBlock::const_pred_iterator BinaryBasicBlock::pred_end() const {
    return predecessors.end();
}

///////////////////////////////////////////////////////////////////////////////

BinaryBasicBlock *BinaryBasicBlocks::find(uint64_t startPc) {
    BinaryBasicBlock dummy(startPc);
    iterator bbIt = basicBlocks.find(&dummy);

    if (bbIt == basicBlocks.end()) {
        return NULL;
    } else {
        return *bbIt;
    }
}

void BinaryBasicBlocks::insert(BinaryBasicBlock *BB) {
    basicBlocks.insert(BB);
}

unsigned BinaryBasicBlocks::size() const {
    return basicBlocks.size();
}

BinaryBasicBlocks::iterator BinaryBasicBlocks::begin() {
    return basicBlocks.begin();
}

BinaryBasicBlocks::iterator BinaryBasicBlocks::end() {
    return basicBlocks.end();
}

BinaryBasicBlocks::const_iterator BinaryBasicBlocks::begin() const {
    return basicBlocks.begin();
}

BinaryBasicBlocks::const_iterator BinaryBasicBlocks::end() const {
    return basicBlocks.end();
}

///////////////////////////////////////////////////////////////////////////////

BinaryFunction::BinaryFunction(std::string n, BinaryBasicBlock *e) : name(n), entry(e) {
    if (e) {
        nodes.insert(e);
    }
}

BinaryBasicBlock *BinaryFunction::getEntryBlock() const {
    return entry;
}

void BinaryFunction::setEntryBlock(BinaryBasicBlock *BB) {
    entry = BB;
}

std::string BinaryFunction::getName() const {
    return name;
}

void BinaryFunction::rename(const std::string &n) {
    name = n;
}

unsigned BinaryFunction::size() const {
    return nodes.size();
}

BinaryFunction::iterator BinaryFunction::begin() {
    return nodes.begin();
}

BinaryFunction::iterator BinaryFunction::end() {
    return nodes.end();
}

BinaryFunction::const_iterator BinaryFunction::begin() const {
    return nodes.begin();
}

BinaryFunction::const_iterator BinaryFunction::end() const {
    return nodes.end();
}

void BinaryFunction::add(BinaryBasicBlock *BB) {
    nodes.insert(BB);
}

void BinaryFunction::add(BinaryBasicBlock *BB, const BinaryBasicBlock::Children &succs) {
    for (BinaryBasicBlock *succ : succs) {
        succ->addPred(BB);
        BB->addSucc(succ);
    }

    nodes.insert(BB);
}

} // namespace llvm
