//===-- Memory.h ------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_MEMORY_H
#define KLEE_MEMORY_H

#include "klee/Expr.h"
#include "Context.h"

#include "klee/util/BitArray.h"
#include "klee/util/ConcreteBuffer.h"
#include "llvm/ADT/StringExtras.h"

#include <inttypes.h>
#include <string>
#include <vector>

namespace klee {

class MemoryObject {
public:
    uint64_t address;

    /// size in bytes
    unsigned size;
    std::string name;

    bool isLocal;
    bool isFixed;

    /// True if this object should always be accessed directly
    /// by its address (i.e., bypassing all ObjectStates).
    /// This means that the object will always contain concrete
    /// values and its conctent will be shared across all states
    /// (unless explicitly saved/restored on state switches -
    /// ObjectState will still be allocated for this purpose).
    bool isSharedConcrete;

    /// True if can be split into smaller objects
    bool isSplittable;

    /// True if this is an S2E physical memory page (or subpage)
    bool isMemoryPage;

    /// True to get notifications when the object becomes fully concrete
    /// or at least one byte becomes symbolic.
    /// If the object is split into multiple ones, the event is triggered
    /// when the entire group of objects gets the property.
    bool doNotifyOnConcretenessChange;

    // DO NOT IMPLEMENT
    MemoryObject(const MemoryObject &b);
    MemoryObject &operator=(const MemoryObject &b);

public:
    // XXX this is just a temp hack, should be removed
    explicit MemoryObject(uint64_t _address)
        : address(_address), size(0), isFixed(true), isSplittable(false), doNotifyOnConcretenessChange(false) {
    }

    MemoryObject(uint64_t _address, unsigned _size, bool _isLocal, bool _isFixed)
        : address(_address), size(_size), name("unnamed"), isLocal(_isLocal), isFixed(_isFixed),
          isSharedConcrete(false), isSplittable(false), isMemoryPage(false), doNotifyOnConcretenessChange(false) {
    }

    ~MemoryObject();

    void setName(const std::string &name) {
        this->name = name;
    }

    ref<ConstantExpr> getBaseExpr() const {
        return ConstantExpr::create(address, Context::get().getPointerWidth());
    }
    ref<ConstantExpr> getSizeExpr() const {
        return ConstantExpr::create(size, Context::get().getPointerWidth());
    }
    ref<Expr> getOffsetExpr(ref<Expr> pointer) const {
        return SubExpr::create(pointer, getBaseExpr());
    }
    uint64_t getOffset(uint64_t pointer) const {
        return pointer - address;
    }
    ref<Expr> getBoundsCheckPointer(ref<Expr> pointer) const {
        return getBoundsCheckOffset(getOffsetExpr(pointer));
    }
    ref<Expr> getBoundsCheckPointer(ref<Expr> pointer, unsigned bytes) const {
        return getBoundsCheckOffset(getOffsetExpr(pointer), bytes);
    }

    ref<Expr> getBoundsCheckOffset(ref<Expr> offset) const {
        if (size == 0) {
            return EqExpr::create(offset, ConstantExpr::alloc(0, Context::get().getPointerWidth()));
        } else {
            return UltExpr::create(offset, getSizeExpr());
        }
    }
    ref<Expr> getBoundsCheckOffset(ref<Expr> offset, unsigned bytes) const {
        if (bytes <= size) {
            return UltExpr::create(offset, ConstantExpr::alloc(size - bytes + 1, Context::get().getPointerWidth()));
        } else {
            return ConstantExpr::alloc(0, Expr::Bool);
        }
    }

    // Split the current object at specified offsets
    void split(std::vector<MemoryObject *> &objects, const std::vector<unsigned> &offsets) const;
};

class ObjectState {
private:
    // XXX(s2e) for now we keep this first to access from C code
    // (yes, we do need to access if really fast)
    BitArrayPtr concreteMask;

    friend class AddressSpace;
    template <typename U> friend class AddressSpaceBase;
    unsigned copyOnWriteOwner; // exclusively for AddressSpace

    friend class ObjectHolder;
    unsigned refCount;

    const MemoryObject *object;

    unsigned size;

    bool readOnly;

    // XXX: made it public for fast access
    ConcreteBufferPtr concreteStore;

    // If the store is shared between object states,
    // indicate the offset of our region
    unsigned storeOffset;

    // XXX cleanup name of flushMask (its backwards or something)
    // mutable because may need flushed during read of const
    mutable BitArrayPtr flushMask;

    std::vector<ref<Expr>> knownSymbolics;

    // mutable because we may need flush during read of const
    mutable UpdateListPtr updates;

private:
    ObjectState();

    // For AddressSpace
    ConcreteBufferPtr getConcreteBufferAs() {
        return concreteStore;
    }

public:
    /// Create a new object state for the given memory object with concrete
    /// contents. The initial contents are undefined, it is the callers
    /// responsibility to initialize the object contents appropriately.
    ObjectState(const MemoryObject *mo);

    /// Create a new object state for the given memory object with symbolic
    /// contents.
    ObjectState(const MemoryObject *mo, const ArrayPtr &array);

    ObjectState(const ObjectState &os);
    ~ObjectState();

    inline const MemoryObject *getObject() const {
        return object;
    }

    void setReadOnly(bool ro) {
        readOnly = ro;
    }

    bool isReadOnly() const {
        return readOnly;
    }

    unsigned getSize() const {
        return size;
    }

    ref<Expr> read(ref<Expr> offset, Expr::Width width) const;
    ref<Expr> read(unsigned offset, Expr::Width width) const;
    ref<Expr> read8(unsigned offset) const;

    // fast-path to get concrete values
    bool readConcrete8(unsigned offset, uint8_t *v) const {
        if (object->isSharedConcrete) {
            *v = ((uint8_t *) object->address)[offset];
            return true;
        } else if (isByteConcrete(offset)) {
            *v = concreteStore->get()[offset + storeOffset];
            return true;
        } else {
            return false;
        }
    }

    // return bytes written.
    void write(unsigned offset, ref<Expr> value);
    void write(ref<Expr> offset, ref<Expr> value);

    void write8(unsigned offset, uint8_t value);
    void write16(unsigned offset, uint16_t value);
    void write32(unsigned offset, uint32_t value);
    void write64(unsigned offset, uint64_t value);

    bool isAllConcrete() const;

    inline bool isConcrete(unsigned offset, Expr::Width width) const {
        if (!concreteMask) {
            return true;
        }

        unsigned size = Expr::getMinBytesForWidth(width);
        for (unsigned i = 0; i < size; ++i) {
            if (!isByteConcrete(offset + i)) {
                return false;
            }
        }
        return true;
    }

    const uint8_t *getConcreteStore(bool allowSymbolic = false) const;
    uint8_t *getConcreteStore(bool allowSymolic = false);

    const ConcreteBufferPtr &getConcreteBuffer() const {
        return concreteStore;
    }

    const BitArrayPtr &getConcreteMask() const {
        return concreteMask;
    }

    // Split the current object at specified offset
    ObjectState *split(MemoryObject *object, unsigned offset) const;

    unsigned getStoreOffset() const {
        return storeOffset;
    }

    unsigned getBitArraySize() const {
        if (!concreteMask) {
            return size;
        }
        return concreteMask->getBitCount();
    }

    void initializeConcreteMask();

private:
    const UpdateListPtr &getUpdates() const;

    ref<Expr> read8(ref<Expr> offset) const;
    void write8(unsigned offset, ref<Expr> value);
    void write8(ref<Expr> offset, ref<Expr> value);

    void fastRangeCheckOffset(ref<Expr> offset, unsigned *base_r, unsigned *size_r) const;
    void flushRangeForRead(unsigned rangeBase, unsigned rangeSize) const;
    void flushRangeForWrite(unsigned rangeBase, unsigned rangeSize);

    inline bool isByteConcrete(unsigned offset) const {
        return !concreteMask || concreteMask->get(storeOffset + offset);
    }

    inline bool isByteFlushed(unsigned offset) const {
        return flushMask && !flushMask->get(offset);
    }

    inline bool isByteKnownSymbolic(unsigned offset) const {
        return knownSymbolics.size() > 0 && knownSymbolics[offset].get();
    }

    inline void markByteConcrete(unsigned offset) {
        if (concreteMask) {
            concreteMask->set(storeOffset + offset);
        }
    }

    void markByteSymbolic(unsigned offset);

    void markByteFlushed(unsigned offset);

    void markByteUnflushed(unsigned offset) {
        if (flushMask) {
            flushMask->set(offset);
        }
    }

    void setKnownSymbolic(unsigned offset, const ref<Expr> &value);

    ObjectState *getCopy(const BitArrayPtr &_concreteMask, const ConcreteBufferPtr &_concreteStore) const;
};

} // End klee namespace

#endif
