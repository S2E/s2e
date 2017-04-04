///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "CFG/BinaryCFG.h"

namespace llvm {

void BinaryBasicBlock::addSucc(BinaryBasicBlock *BB) {
    successors.push_back(BB);
}

void BinaryBasicBlock::addPred(BinaryBasicBlock *BB) {
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
