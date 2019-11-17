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

MemoryObject::~MemoryObject() {
    if (!isFixed) {
        free((void *) address);
    }
}

void MemoryObject::split(std::vector<MemoryObject *> &objects, const std::vector<unsigned> &offsets) const {
    assert(isSplittable);

    unsigned count = offsets.size();

    for (unsigned i = 0; i < count; ++i) {
        unsigned offset = offsets[i];
        unsigned nsize;

        if (i < count - 1) {
            nsize = offsets[i + 1] - offset;
        } else {
            nsize = size - offset;
        }

        MemoryObject *obj = new MemoryObject(address, nsize, isFixed);
        obj->address = address + offset;
        obj->size = nsize;
        obj->isSplittable = false;
        obj->isMemoryPage = isMemoryPage;
        objects.push_back(obj);
    }
}

/***/

ObjectState::ObjectState()
    : copyOnWriteOwner(0), refCount(0), object(nullptr), size(0), readOnly(false), m_notifyOnConcretenessChange(false),
      storeOffset(0), updates(UpdateList::create(nullptr, 0)) {
}

ObjectState::ObjectState(const MemoryObject *mo)
    : copyOnWriteOwner(0), refCount(0), object(nullptr), size(0), readOnly(false), m_notifyOnConcretenessChange(false),
      storeOffset(0), updates(UpdateList::create(nullptr, 0)) {

    this->object = mo;
    this->size = mo->size;
    this->concreteStore = ConcreteBuffer::create(mo->size);
}

ObjectState::ObjectState(const MemoryObject *mo, const ArrayPtr &array)
    : copyOnWriteOwner(0), refCount(0), object(nullptr), size(0), readOnly(false), m_notifyOnConcretenessChange(false),
      storeOffset(0), updates(UpdateList::create(array, 0)) {

    this->object = mo;
    this->size = mo->size;
    this->concreteStore = ConcreteBuffer::create(mo->size);
}

ObjectState::ObjectState(const ObjectState &os)
    : copyOnWriteOwner(0), refCount(0), object(nullptr), size(0), readOnly(false), storeOffset(0),
      updates(UpdateList::create(nullptr, 0)) {
    assert(!os.readOnly && "no need to copy read only object?");
    assert(!os.concreteMask || (os.size == os.concreteMask->getBitCount()));

    this->m_notifyOnConcretenessChange = os.m_notifyOnConcretenessChange;
    this->concreteMask = os.concreteMask ? BitArray::create(os.concreteMask) : nullptr;
    this->copyOnWriteOwner = os.copyOnWriteOwner;
    this->refCount = 0;
    this->object = os.object;
    this->size = os.size;
    this->readOnly = os.readOnly;
    this->concreteStore = ConcreteBuffer::create(os.concreteStore);
    this->storeOffset = os.storeOffset;
    this->flushMask = os.flushMask ? BitArray::create(os.flushMask) : nullptr;
    this->knownSymbolics = os.knownSymbolics;
    this->updates = UpdateList::create(os.updates->getRoot(), os.updates->getHead());
}

ObjectState::~ObjectState() {
}

/***/

ObjectState *ObjectState::split(MemoryObject *newObject, unsigned offset) const {
    assert(this->object->isSplittable);
    assert(newObject->size <= this->object->size);
    assert(offset + newObject->size <= this->object->size);
    assert(flushMask == NULL);
    assert(updates->getSize() == 0);
    assert(readOnly == false);

    ObjectState *ret = new ObjectState();
    ret->object = newObject;
    ret->concreteMask = concreteMask;
    ret->concreteStore = concreteStore;
    ret->storeOffset = offset;

    ret->size = newObject->size;
    ret->readOnly = readOnly;
    ret->m_notifyOnConcretenessChange = m_notifyOnConcretenessChange;

    // XXX: is this really correct? Don't we need to take a subset?
    ret->updates = UpdateList::create(updates->getRoot(), updates->getHead());

    if (knownSymbolics.size() > 0) {
        ret->knownSymbolics.resize(newObject->size);
        for (unsigned i = 0; i < newObject->size; i++) {
            ret->knownSymbolics[i] = knownSymbolics[i + offset];
        }
    }

    return ret;
}

void ObjectState::initializeConcreteMask() {
    if (!concreteMask) {
        concreteMask = BitArray::create(size, true);
    }
}

ObjectState *ObjectState::getCopy(const BitArrayPtr &_concreteMask, const ConcreteBufferPtr &_concreteStore) const {
    ObjectState *ret = new ObjectState();
    ret->object = object;
    ret->concreteMask = _concreteMask;
    ret->concreteStore = _concreteStore;
    ret->storeOffset = storeOffset;
    ret->size = size;
    ret->readOnly = readOnly;
    ret->m_notifyOnConcretenessChange = m_notifyOnConcretenessChange;

    ret->updates = UpdateList::create(updates->getRoot(), updates->getHead());

    if (flushMask) {
        ret->flushMask = BitArray::create(flushMask);
    }

    ret->knownSymbolics = knownSymbolics;

    return ret;
}

/***/

const UpdateListPtr &ObjectState::getUpdates() const {
    // Constant arrays are created lazily.
    if (!updates->getRoot()) {
        // Collect the list of writes, with the oldest writes first.

        // FIXME: We should be able to do this more efficiently, we just need to be
        // careful to get the interaction with the cache right. In particular we
        // should avoid creating UpdateNode instances we never use.
        unsigned NumWrites = updates->getHead() ? updates->getHead()->getSize() : 0;
        std::vector<std::pair<ref<Expr>, ref<Expr>>> Writes(NumWrites);
        auto un = updates->getHead();
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
        auto array =
            Array::create("const_arr" + llvm::utostr(++id), size, &Contents[0], &Contents[0] + Contents.size());
        updates = UpdateList::create(array, 0);

        // Apply the remaining (non-constant) writes.
        for (; Begin != End; ++Begin)
            updates->extend(Writes[Begin].first, Writes[Begin].second);
    }

    return updates;
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
    if (!flushMask) {
        flushMask = BitArray::create(size, true);
    }

    for (unsigned offset = rangeBase; offset < rangeBase + rangeSize; offset++) {
        if (!isByteFlushed(offset)) {
            if (isByteConcrete(offset)) {
                updates->extend(ConstantExpr::create(offset, Expr::Int32),
                                ConstantExpr::create(concreteStore->get()[offset + storeOffset], Expr::Int8));
            } else {
                assert(isByteKnownSymbolic(offset) && "invalid bit set in flushMask");
                updates->extend(ConstantExpr::create(offset, Expr::Int32), knownSymbolics[offset]);
            }

            flushMask->unset(offset);
        }
    }
}

void ObjectState::flushRangeForWrite(unsigned rangeBase, unsigned rangeSize) {
    if (!flushMask) {
        flushMask = BitArray::create(size, true);
    }

    for (unsigned offset = rangeBase; offset < rangeBase + rangeSize; offset++) {
        if (!isByteFlushed(offset)) {
            if (isByteConcrete(offset)) {
                updates->extend(ConstantExpr::create(offset, Expr::Int32),
                                ConstantExpr::create(concreteStore->get()[offset + storeOffset], Expr::Int8));
                markByteSymbolic(offset);
            } else {
                assert(isByteKnownSymbolic(offset) && "invalid bit set in flushMask");
                updates->extend(ConstantExpr::create(offset, Expr::Int32), knownSymbolics[offset]);
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
    if (!concreteMask) {
        concreteMask = BitArray::create(size, true);
    }
    concreteMask->unset(storeOffset + offset);
}

void ObjectState::markByteFlushed(unsigned offset) {
    if (!flushMask) {
        flushMask = BitArray::create(size, false);
    } else {
        flushMask->unset(offset);
    }
}

inline void ObjectState::setKnownSymbolic(unsigned offset, const ref<Expr> &value) {
    if (knownSymbolics.size() > 0) {
        knownSymbolics[offset] = value;
    } else {
        if (!value.isNull()) {
            knownSymbolics.resize(size);
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
        klee_warning_once(0, "flushing %d bytes on read, may be slow and/or crash", size);
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
        klee_warning_once(0, "flushing %d bytes on read, may be slow and/or crash", size);
    }

    updates->extend(ZExtExpr::create(offset, Expr::Int32), value);
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
