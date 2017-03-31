//===-- Memory.cpp --------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Common.h"

#include "klee/Memory.h"

#include "klee/Context.h"
#include "klee/Expr.h"
#include "klee/Solver.h"
#include "klee/util/BitArray.h"

#include "klee/ObjectHolder.h"

#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Value.h>
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include <cassert>
#include <iostream>
#include <sstream>

using namespace llvm;
using namespace klee;

namespace {
cl::opt<bool> UseConstantArrays("use-constant-arrays", cl::init(true));
}

InitialStateAllocator *InitialStateAllocator::s_allocator = NULL;

bool InitialStateAllocator::initialize(uint64_t pageCount) {
    return initializeInternal(pageCount * (sizeof(MemoryObject) + sizeof(ObjectState)));
}

/***/

ObjectHolder::ObjectHolder(const ObjectHolder &b) : os(b.os) {
    if (os)
        ++os->refCount;
}

ObjectHolder::ObjectHolder(ObjectState *_os) : os(_os) {
    if (os)
        ++os->refCount;
}

ObjectHolder::~ObjectHolder() {
    if (os && --os->refCount == 0)
        delete os;
}

ObjectHolder &ObjectHolder::operator=(const ObjectHolder &b) {
    if (b.os)
        ++b.os->refCount;
    if (os && --os->refCount == 0)
        delete os;
    os = b.os;
    return *this;
}

/***/

int MemoryObject::counter = 0;

MemoryObject::~MemoryObject() {
}

void MemoryObject::getAllocInfo(std::string &result) const {
    llvm::raw_string_ostream info(result);

    info << "MO" << id << "[" << size << "]";

    if (allocSite) {
        info << " allocated at ";
        if (const Instruction *i = dyn_cast<Instruction>(allocSite)) {
            info << i->getParent()->getParent()->getName().str() << "():";
            info << *i;
        } else if (const GlobalValue *gv = dyn_cast<GlobalValue>(allocSite)) {
            info << "global:" << gv->getName().str();
        } else {
            info << "value:" << *allocSite;
        }
    } else {
        info << " (no allocation info)";
    }

    info.flush();
}

void MemoryObject::split(std::vector<MemoryObject *> &objects, const std::vector<unsigned> &offsets) const {
    assert(isSplittable);

    // XXX: what do we do with these?
    assert(cexPreferences.size() == 0);
    unsigned count = offsets.size();

    for (unsigned i = 0; i < count; ++i) {
        unsigned offset = offsets[i];
        unsigned nsize;

        if (i < count - 1) {
            nsize = offsets[i + 1] - offset;
        } else {
            nsize = size - offset;
        }

        MemoryObject *obj = new MemoryObject(address, nsize, isLocal, isGlobal, isFixed, allocSite);
        obj->address = address + offset;
        obj->size = nsize;
        obj->isSplittable = false;
        obj->isMemoryPage = isMemoryPage;
        obj->isUserSpecified = isUserSpecified;
        obj->doNotifyOnConcretenessChange = doNotifyOnConcretenessChange;
        objects.push_back(obj);
    }
}

/***/

uint64_t ObjectState::count = 0;
uint64_t ObjectState::ssize = 0;

ObjectState::ObjectState()
    : concreteMask(0), copyOnWriteOwner(0), refCount(0), object(NULL), concreteStore(NULL), storeOffset(0),
      flushMask(0), knownSymbolics(0), updates(0, 0), size(0), readOnly(false) {
}

ObjectState::ObjectState(const MemoryObject *mo)
    : concreteMask(0), copyOnWriteOwner(0), refCount(0), object(mo), concreteStore(new ConcreteBuffer(mo->size)),
      storeOffset(0), flushMask(0), knownSymbolics(0), updates(0, 0), size(mo->size), readOnly(false) {
    if (!UseConstantArrays) {
        // FIXME: Leaked.
        static unsigned id = 0;
        const Array *array = new Array("tmp_arr" + llvm::utostr(++id), size);
        updates = UpdateList(array, 0);
    }
    ++count;
    ssize += mo->size;
}

ObjectState::ObjectState(const MemoryObject *mo, const Array *array)
    : concreteMask(0), copyOnWriteOwner(0), refCount(0), object(mo), concreteStore(new ConcreteBuffer(mo->size)),
      storeOffset(0), flushMask(0), knownSymbolics(0), updates(array, 0), size(mo->size), readOnly(false) {
    makeSymbolic();
    ++count;
    ssize += mo->size;
}

ObjectState::ObjectState(const ObjectState &os)
    : concreteMask(os.concreteMask ? new BitArray(*os.concreteMask, os.size) : 0), copyOnWriteOwner(0), refCount(0),
      object(os.object), concreteStore(new ConcreteBuffer(os.size)), storeOffset(0),
      flushMask(os.flushMask ? new BitArray(*os.flushMask, os.size) : 0), knownSymbolics(0), updates(os.updates),
      size(os.size), readOnly(false) {
    assert(!os.readOnly && "no need to copy read only object?");

    assert(!os.concreteMask || (os.size == os.concreteMask->getBitCount()));

    if (os.knownSymbolics) {
        knownSymbolics = new ref<Expr>[ size ];
        for (unsigned i = 0; i < size; i++)
            knownSymbolics[i] = os.knownSymbolics[i];
    }
    ++count;
    ssize += os.size;
    memcpy(concreteStore->get(), os.concreteStore->get(), size * sizeof(*concreteStore->get()));
}

ObjectState::~ObjectState() {
    if (concreteMask)
        concreteMask->decref();
    if (flushMask)
        flushMask->decref();
    if (knownSymbolics)
        delete[] knownSymbolics;
    concreteStore->decref();
    --count;
    ssize -= size;
}

/***/

ObjectState *ObjectState::split(MemoryObject *newObject, unsigned offset) const {
    assert(this->object->isSplittable);
    assert(newObject->size <= this->object->size);
    assert(offset + newObject->size <= this->object->size);
    assert(flushMask == NULL);
    assert(updates.getSize() == 0);
    assert(readOnly == false);

    ObjectState *ret = new ObjectState();
    ret->object = newObject;

    ret->concreteMask = concreteMask;
    ret->concreteMask->incref();
    ret->concreteStore = concreteStore;
    ret->concreteStore->incref();
    ret->storeOffset = offset;

    ret->size = newObject->size;
    ret->readOnly = readOnly;
    ret->updates = updates;

    if (knownSymbolics) {
        ret->knownSymbolics = new ref<Expr>[ newObject->size ];
        for (unsigned i = 0; i < newObject->size; i++)
            ret->knownSymbolics[i] = knownSymbolics[i + offset];
    }

    return ret;
}

void ObjectState::initializeConcreteMask() {
    if (!concreteMask) {
        concreteMask = new BitArray(size, true);
    }
}

ObjectState *ObjectState::getCopy(BitArray *_concreteMask, ConcreteBuffer *_concreteStore) const {
    ObjectState *ret = new ObjectState();
    ret->object = object;
    ret->concreteMask = _concreteMask;
    ret->concreteMask->incref();
    ret->concreteStore = _concreteStore;
    ret->concreteStore->incref();
    ret->storeOffset = storeOffset;
    ret->size = size;
    ret->readOnly = readOnly;

    ret->updates = updates;

    if (flushMask) {
        ret->flushMask = new BitArray(*flushMask, size);
    }

    if (knownSymbolics) {
        ret->knownSymbolics = new ref<Expr>[ size ];
        for (unsigned i = 0; i < size; i++)
            ret->knownSymbolics[i] = knownSymbolics[i];
    }

    return ret;
}

/***/

const UpdateList &ObjectState::getUpdates() const {
    // Constant arrays are created lazily.
    if (!updates.getRoot()) {
        // Collect the list of writes, with the oldest writes first.

        // FIXME: We should be able to do this more efficiently, we just need to be
        // careful to get the interaction with the cache right. In particular we
        // should avoid creating UpdateNode instances we never use.
        unsigned NumWrites = updates.getHead() ? updates.getHead()->getSize() : 0;
        std::vector<std::pair<ref<Expr>, ref<Expr>>> Writes(NumWrites);
        const UpdateNode *un = updates.getHead();
        for (unsigned i = NumWrites; i != 0; un = un->getNext()) {
            --i;
            Writes[i] = std::make_pair(un->getIndex(), un->getValue());
        }

        std::vector<ref<ConstantExpr>> Contents(size);

        // Initialize to zeros.
        for (unsigned i = 0, e = size; i != e; ++i)
            Contents[i] = ConstantExpr::create(0, Expr::Int8);

        // Pull off as many concrete writes as we can.
        unsigned Begin = 0, End = Writes.size();
        for (; Begin != End; ++Begin) {
            // Push concrete writes into the constant array.
            ConstantExpr *Index = dyn_cast<ConstantExpr>(Writes[Begin].first);
            if (!Index)
                break;

            ConstantExpr *Value = dyn_cast<ConstantExpr>(Writes[Begin].second);
            if (!Value)
                break;

            Contents[Index->getZExtValue()] = Value;
        }

        // FIXME: We should unique these, there is no good reason to create multiple
        // ones.

        // Start a new update list.
        // FIXME: Leaked.
        static unsigned id = 0;
        const Array *array =
            new Array("const_arr" + llvm::utostr(++id), size, &Contents[0], &Contents[0] + Contents.size());
        updates = UpdateList(array, 0);

        // Apply the remaining (non-constant) writes.
        for (; Begin != End; ++Begin)
            updates.extend(Writes[Begin].first, Writes[Begin].second);
    }

    return updates;
}

void ObjectState::makeConcrete() {
    if (concreteMask)
        concreteMask->decref();
    if (flushMask)
        flushMask->decref();
    if (knownSymbolics)
        delete[] knownSymbolics;
    concreteMask = 0;
    flushMask = 0;
    knownSymbolics = 0;
}

void ObjectState::makeSymbolic() {
    assert(!updates.getHead() && "XXX makeSymbolic of objects with symbolic values is unsupported");

    // XXX simplify this, can just delete various arrays I guess
    for (unsigned i = 0; i < size; i++) {
        markByteSymbolic(i);
        setKnownSymbolic(i, 0);
        markByteFlushed(i);
    }
}

void ObjectState::initializeToZero() {
    makeConcrete();
    memset(concreteStore->get() + storeOffset, 0, size);
}

void ObjectState::initializeToRandom() {
    makeConcrete();
    uint8_t *store = concreteStore->get() + storeOffset;
    for (unsigned i = 0; i < size; i++) {
        // randomly selected by 256 sided die
        store[i] = 0xAB;
    }
}

/*
Cache Invariants
--
isByteKnownSymbolic(i) => !isByteConcrete(i)
isByteConcrete(i) => !isByteKnownSymbolic(i)
!isByteFlushed(i) => (isByteConcrete(i) || isByteKnownSymbolic(i))
 */

void ObjectState::fastRangeCheckOffset(ref<Expr> offset, unsigned *base_r, unsigned *size_r) const {
    *base_r = 0;
    *size_r = size;
}

void ObjectState::flushRangeForRead(unsigned rangeBase, unsigned rangeSize) const {
    if (!flushMask)
        flushMask = new BitArray(size, true);

    for (unsigned offset = rangeBase; offset < rangeBase + rangeSize; offset++) {
        if (!isByteFlushed(offset)) {
            if (isByteConcrete(offset)) {
                updates.extend(ConstantExpr::create(offset, Expr::Int32),
                               ConstantExpr::create(concreteStore->get()[offset + storeOffset], Expr::Int8));
            } else {
                assert(isByteKnownSymbolic(offset) && "invalid bit set in flushMask");
                updates.extend(ConstantExpr::create(offset, Expr::Int32), knownSymbolics[offset]);
            }

            flushMask->unset(offset);
        }
    }
}

void ObjectState::flushRangeForWrite(unsigned rangeBase, unsigned rangeSize) {
    if (!flushMask)
        flushMask = new BitArray(size, true);

    for (unsigned offset = rangeBase; offset < rangeBase + rangeSize; offset++) {
        if (!isByteFlushed(offset)) {
            if (isByteConcrete(offset)) {
                updates.extend(ConstantExpr::create(offset, Expr::Int32),
                               ConstantExpr::create(concreteStore->get()[offset + storeOffset], Expr::Int8));
                markByteSymbolic(offset);
            } else {
                assert(isByteKnownSymbolic(offset) && "invalid bit set in flushMask");
                updates.extend(ConstantExpr::create(offset, Expr::Int32), knownSymbolics[offset]);
                setKnownSymbolic(offset, 0);
            }

            flushMask->unset(offset);
        } else {
            // flushed bytes that are written over still need
            // to be marked out
            if (isByteConcrete(offset)) {
                markByteSymbolic(offset);
            } else if (isByteKnownSymbolic(offset)) {
                setKnownSymbolic(offset, 0);
            }
        }
    }
}

bool ObjectState::isAllConcrete() const {
    return !concreteMask || concreteMask->isAllOnes(size);
}

const uint8_t *ObjectState::getConcreteStore(bool allowSymbolic) const {
    if (!allowSymbolic && !isAllConcrete()) {
        return NULL;
    }
    return concreteStore->get() + storeOffset;
}

uint8_t *ObjectState::getConcreteStore(bool allowSymbolic) {
    if (!allowSymbolic && !isAllConcrete()) {
        return NULL;
    }
    return concreteStore->get() + storeOffset;
}

void ObjectState::markByteSymbolic(unsigned offset) {
    if (!concreteMask)
        concreteMask = new BitArray(size, true);
    concreteMask->unset(storeOffset + offset);
}

void ObjectState::markByteFlushed(unsigned offset) {
    if (!flushMask) {
        flushMask = new BitArray(size, false);
    } else {
        flushMask->unset(offset);
    }
}

inline void ObjectState::setKnownSymbolic(unsigned offset, Expr *value /* can be null */) {
    if (knownSymbolics) {
        knownSymbolics[offset] = value;
    } else {
        if (value) {
            knownSymbolics = new ref<Expr>[ size ];
            knownSymbolics[offset] = value;
        }
    }
}

/***/

ref<Expr> ObjectState::read8(unsigned offset) const {
    if (!object->isSharedConcrete) {
        if (isByteConcrete(offset)) {
            return ConstantExpr::create(concreteStore->get()[offset + storeOffset], Expr::Int8);
        } else if (isByteKnownSymbolic(offset)) {
            return knownSymbolics[offset];
        } else {
            assert(isByteFlushed(offset) && "unflushed byte without cache value");
            assert(offset < size);
            return ReadExpr::create(getUpdates(), ConstantExpr::create(offset, Expr::Int32));
        }
    } else {
        return ConstantExpr::create(((uint8_t *) object->address)[offset], Expr::Int8);
    }
}

ref<Expr> ObjectState::read8(ref<Expr> offset) const {
    assert(!isa<ConstantExpr>(offset) && "constant offset passed to symbolic read8");
    assert(!object->isSharedConcrete && "read at non-constant offset for shared concrete object");
    unsigned base, size;
    fastRangeCheckOffset(offset, &base, &size);
    flushRangeForRead(base, size);

    if (size > 4096) {
        std::string allocInfo;
        object->getAllocInfo(allocInfo);
        klee_warning_once(0, "flushing %d bytes on read, may be slow and/or crash: %s", size, allocInfo.c_str());
    }

    return ReadExpr::create(getUpdates(), ZExtExpr::create(offset, Expr::Int32));
}

void ObjectState::write8(unsigned offset, uint8_t value) {
    // assert(read_only == false && "writing to read-only object!");
    if (!object->isSharedConcrete) {
        concreteStore->get()[offset + storeOffset] = value;
        setKnownSymbolic(offset, 0);

        markByteConcrete(offset);
        markByteUnflushed(offset);
    } else {
        ((uint8_t *) object->address)[offset] = value;
    }
}

void ObjectState::write8(unsigned offset, ref<Expr> value) {
    // can happen when ExtractExpr special cases
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(value)) {
        write8(offset, (uint8_t) CE->getZExtValue(8));
    } else {
        assert(!object->isSharedConcrete && "write of non-constant value to shared concrete object");
        setKnownSymbolic(offset, value.get());

        markByteSymbolic(offset);
        markByteUnflushed(offset);
    }
}

void ObjectState::write8(ref<Expr> offset, ref<Expr> value) {
    assert(!isa<ConstantExpr>(offset) && "constant offset passed to symbolic write8");
    assert(!object->isSharedConcrete && "write at non-constant offset for shared concrete object");
    unsigned base, size;
    fastRangeCheckOffset(offset, &base, &size);
    flushRangeForWrite(base, size);

    if (size > 4096) {
        std::string allocInfo;
        object->getAllocInfo(allocInfo);
        klee_warning_once(0, "flushing %d bytes on read, may be slow and/or crash: %s", size, allocInfo.c_str());
    }

    updates.extend(ZExtExpr::create(offset, Expr::Int32), value);
}

/***/

ref<Expr> ObjectState::read(ref<Expr> offset, Expr::Width width) const {
    // Truncate offset to 32-bits.
    offset = ZExtExpr::create(offset, Expr::Int32);

    // Check for reads at constant offsets.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(offset))
        return read(CE->getZExtValue(32), width);

    // Treat bool specially, it is the only non-byte sized write we allow.
    if (width == Expr::Bool)
        return ExtractExpr::create(read8(offset), 0, Expr::Bool);

    // Otherwise, follow the slow general case.
    unsigned NumBytes = width / 8;
    assert(width == NumBytes * 8 && "Invalid write size!");
    ref<Expr> Res(0);
    for (unsigned i = 0; i != NumBytes; ++i) {
        unsigned idx = Context::get().isLittleEndian() ? i : (NumBytes - i - 1);
        ref<Expr> Byte = read8(AddExpr::create(offset, ConstantExpr::create(idx, Expr::Int32)));
        Res = idx ? ConcatExpr::create(Byte, Res) : Byte;
    }

    return Res;
}

ref<Expr> ObjectState::read(unsigned offset, Expr::Width width) const {
    // Treat bool specially, it is the only non-byte sized write we allow.
    if (width == Expr::Bool)
        return ExtractExpr::create(read8(offset), 0, Expr::Bool);

    // Otherwise, follow the slow general case.
    unsigned NumBytes = width / 8;
    assert(width == NumBytes * 8 && "Invalid write size!");
    ref<Expr> Res(0);
    for (unsigned i = 0; i != NumBytes; ++i) {
        unsigned idx = Context::get().isLittleEndian() ? i : (NumBytes - i - 1);
        ref<Expr> Byte = read8(offset + idx);
        Res = idx ? ConcatExpr::create(Byte, Res) : Byte;
    }

    return Res;
}

void ObjectState::write(ref<Expr> offset, ref<Expr> value) {
    // Truncate offset to 32-bits.
    offset = ZExtExpr::create(offset, Expr::Int32);

    // Check for writes at constant offsets.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(offset)) {
        write(CE->getZExtValue(32), value);
        return;
    }

    // Treat bool specially, it is the only non-byte sized write we allow.
    Expr::Width w = value->getWidth();
    if (w == Expr::Bool) {
        write8(offset, ZExtExpr::create(value, Expr::Int8));
        return;
    }

    // Otherwise, follow the slow general case.
    unsigned NumBytes = w / 8;
    assert(w == NumBytes * 8 && "Invalid write size!");
    for (unsigned i = 0; i != NumBytes; ++i) {
        unsigned idx = Context::get().isLittleEndian() ? i : (NumBytes - i - 1);
        write8(AddExpr::create(offset, ConstantExpr::create(idx, Expr::Int32)),
               ExtractExpr::create(value, 8 * i, Expr::Int8));
    }
}

void ObjectState::write(unsigned offset, ref<Expr> value) {
    // Check for writes of constant values.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(value)) {
        Expr::Width w = CE->getWidth();
        if (w <= 64) {
            uint64_t val = CE->getZExtValue();
            switch (w) {
                default:
                    assert(0 && "Invalid write size!");
                case Expr::Bool:
                case Expr::Int8:
                    write8(offset, val);
                    return;
                case Expr::Int16:
                    write16(offset, val);
                    return;
                case Expr::Int32:
                    write32(offset, val);
                    return;
                case Expr::Int64:
                    write64(offset, val);
                    return;
            }
        }
    }

    // Treat bool specially, it is the only non-byte sized write we allow.
    Expr::Width w = value->getWidth();
    if (w == Expr::Bool) {
        write8(offset, ZExtExpr::create(value, Expr::Int8));
        return;
    }

    // Otherwise, follow the slow general case.
    unsigned NumBytes = w / 8;
    assert(w == NumBytes * 8 && "Invalid write size!");
    for (unsigned i = 0; i != NumBytes; ++i) {
        unsigned idx = Context::get().isLittleEndian() ? i : (NumBytes - i - 1);
        write8(offset + idx, ExtractExpr::create(value, 8 * i, Expr::Int8));
    }
}

void ObjectState::write16(unsigned offset, uint16_t value) {
    unsigned NumBytes = 2;
    for (unsigned i = 0; i != NumBytes; ++i) {
        unsigned idx = Context::get().isLittleEndian() ? i : (NumBytes - i - 1);
        write8(offset + idx, (uint8_t)(value >> (8 * i)));
    }
}

void ObjectState::write32(unsigned offset, uint32_t value) {
    unsigned NumBytes = 4;
    for (unsigned i = 0; i != NumBytes; ++i) {
        unsigned idx = Context::get().isLittleEndian() ? i : (NumBytes - i - 1);
        write8(offset + idx, (uint8_t)(value >> (8 * i)));
    }
}

void ObjectState::write64(unsigned offset, uint64_t value) {
    unsigned NumBytes = 8;
    for (unsigned i = 0; i != NumBytes; ++i) {
        unsigned idx = Context::get().isLittleEndian() ? i : (NumBytes - i - 1);
        write8(offset + idx, (uint8_t)(value >> (8 * i)));
    }
}

void ObjectState::print() {
    std::cerr << "-- ObjectState --\n";
    std::cerr << "\tMemoryObject ID: " << object->id << "\n";
    std::cerr << "\tRoot Object: " << updates.getRoot() << "\n";
    std::cerr << "\tSize: " << size << "\n";

    std::cerr << "\tBytes:\n";
    for (unsigned i = 0; i < size; i++) {
        std::cerr << "\t\t[" << i << "]"
                  << " concrete? " << isByteConcrete(i) << " known-sym? " << isByteKnownSymbolic(i) << " flushed? "
                  << isByteFlushed(i) << " = ";
        ref<Expr> e = read8(i);
        std::cerr << e << "\n";
    }

    std::cerr << "\tUpdates:\n";
    for (const UpdateNode *un = updates.getHead(); un; un = un->getNext()) {
        std::cerr << "\t\t[" << un->getIndex() << "] = " << un->getValue() << "\n";
    }
}
