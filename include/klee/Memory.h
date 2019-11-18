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
#include <stdlib.h>
#include <string>
#include <vector>

#include <boost/intrusive_ptr.hpp>

namespace klee {

struct ObjectKey {
    uint64_t address;
    unsigned size;

    ObjectKey() : address(0), size(0) {
    }

    ref<ConstantExpr> getBaseExpr() const {
        return ConstantExpr::create(address, Context::get().getPointerWidth());
    }

    bool operator==(const ObjectKey &a) const {
        return a.address == address && a.size == size;
    }

    bool operator!=(const ObjectKey &a) const {
        return !(*this == a);
    }

    bool operator<(const ObjectKey &a) const {
        return address + size <= a.address;
    }
};

/// Function object ordering ObjectKey's by address and size.
struct ObjectKeyLTS {
    bool operator()(const ObjectKey &a, const ObjectKey &b) const {
        return a.address + a.size <= b.address;
    }
};

class ObjectState;
typedef boost::intrusive_ptr<ObjectState> ObjectStatePtr;
typedef boost::intrusive_ptr<const ObjectState> ObjectStateConstPtr;

class ObjectState {
private:
    // XXX(s2e) for now we keep this first to access from C code
    // (yes, we do need to access if really fast)
    BitArrayPtr concreteMask;

    template <typename U> friend class AddressSpaceBase;
    unsigned copyOnWriteOwner; // exclusively for AddressSpace

    mutable std::atomic<unsigned> m_refCount;

    uint64_t m_address;
    unsigned m_size;

    // TODO: make it copy-on-write
    std::string m_name;

    bool m_fixed;

    /// The pointer is equal to m_address and is shared between all copies
    /// of this object.
    std::shared_ptr<uint8_t> m_fixedBuffer;

    /// True if can be split into smaller objects
    bool m_splittable;

    bool readOnly;

    /// True to get notifications when the object becomes fully concrete
    /// or at least one byte becomes symbolic.
    /// If the object is split into multiple ones, the event is triggered
    /// when the entire group of objects gets the property.
    bool m_notifyOnConcretenessChange;

    /// True if this is an S2E physical memory page (or subpage)
    bool m_isMemoryPage;

    /// True if this object should always be accessed directly
    /// by its address (i.e., bypassing all ObjectStates).
    /// This means that the object will always contain concrete
    /// values and its conctent will be shared across all states
    /// (unless explicitly saved/restored on state switches -
    /// ObjectState will still be allocated for this purpose).
    bool m_isSharedConcrete;

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
    // For AddressSpace
    ConcreteBufferPtr getConcreteBufferAs() {
        return concreteStore;
    }

    ObjectState();

    /// Create a new object state for the given memory object with concrete
    /// contents. The initial contents are undefined, it is the callers
    /// responsibility to initialize the object contents appropriately.
    ObjectState(uint64_t address, uint64_t size, bool fixed);

    ObjectState(const ObjectState &os);

public:
    ~ObjectState();

    static ObjectStatePtr allocate(uint64_t address, uint64_t size, bool isFixed);
    ObjectStatePtr copy() const {
        return new ObjectState(*this);
    }

    ObjectStatePtr copy(const BitArrayPtr &_concreteMask, const ConcreteBufferPtr &_concreteStore) const;

    const std::string &getName() const {
        return m_name;
    }

    void setName(const std::string &name) {
        m_name = name;
    }

    ObjectKey getKey() const {
        ObjectKey key;
        key.address = m_address;
        key.size = m_size;
        return key;
    }

    void setReadOnly(bool ro) {
        readOnly = ro;
    }

    bool isReadOnly() const {
        return readOnly;
    }

    bool isSplittable() const {
        return m_splittable;
    }

    void setSplittable(bool b) {
        m_splittable = b;
    }

    inline bool notifyOnConcretenessChange() const {
        return m_notifyOnConcretenessChange;
    }

    inline void setNotifyOnConcretenessChange(bool v) {
        m_notifyOnConcretenessChange = v;
    }

    inline bool isMemoryPage() const {
        return m_isMemoryPage;
    }

    inline void setMemoryPage(bool b) {
        m_isMemoryPage = b;
    }

    inline bool isSharedConcrete() const {
        return m_isSharedConcrete;
    }

    inline void setSharedConcrete(bool b) {
        m_isSharedConcrete = b;
    }

    unsigned getSize() const {
        return m_size;
    }

    uint64_t getAddress() const {
        return m_address;
    }

    unsigned getOwnerId() const {
        return copyOnWriteOwner;
    }

    void setOwnerId(unsigned id) {
        copyOnWriteOwner = id;
    }

    ref<Expr> read(ref<Expr> offset, Expr::Width width) const;
    ref<Expr> read(unsigned offset, Expr::Width width) const;
    ref<Expr> read8(unsigned offset) const;

    // fast-path to get concrete values
    bool readConcrete8(unsigned offset, uint8_t *v) const {
        if (m_isSharedConcrete) {
            *v = ((uint8_t *) m_address)[offset];
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
    ObjectStatePtr split(unsigned offset, unsigned newSize) const;

    unsigned getStoreOffset() const {
        return storeOffset;
    }

    unsigned getBitArraySize() const {
        if (!concreteMask) {
            return m_size;
        }
        return concreteMask->getBitCount();
    }

    void initializeConcreteMask();

    uint64_t getOffset(uint64_t pointer) const {
        return pointer - m_address;
    }

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

public:
    ref<ConstantExpr> getBaseExpr() const {
        return ConstantExpr::create(m_address, Context::get().getPointerWidth());
    }
    ref<ConstantExpr> getSizeExpr() const {
        return ConstantExpr::create(m_size, Context::get().getPointerWidth());
    }
    ref<Expr> getOffsetExpr(ref<Expr> pointer) const {
        return SubExpr::create(pointer, getBaseExpr());
    }

    ref<Expr> getBoundsCheckPointer(ref<Expr> pointer) const {
        return getBoundsCheckOffset(getOffsetExpr(pointer));
    }
    ref<Expr> getBoundsCheckPointer(ref<Expr> pointer, unsigned bytes) const {
        return getBoundsCheckOffset(getOffsetExpr(pointer), bytes);
    }

    ref<Expr> getBoundsCheckOffset(ref<Expr> offset) const {
        if (m_size == 0) {
            return EqExpr::create(offset, ConstantExpr::alloc(0, Context::get().getPointerWidth()));
        } else {
            return UltExpr::create(offset, getSizeExpr());
        }
    }
    ref<Expr> getBoundsCheckOffset(ref<Expr> offset, unsigned bytes) const {
        if (bytes <= m_size) {
            return UltExpr::create(offset, ConstantExpr::alloc(m_size - bytes + 1, Context::get().getPointerWidth()));
        } else {
            return ConstantExpr::alloc(0, Expr::Bool);
        }
    }

    friend void intrusive_ptr_add_ref(ObjectState *ptr);
    friend void intrusive_ptr_release(ObjectState *ptr);
    friend void intrusive_ptr_add_ref(const ObjectState *ptr);
    friend void intrusive_ptr_release(const ObjectState *ptr);
};

inline void intrusive_ptr_add_ref(ObjectState *ptr) {
    ++ptr->m_refCount;
}

inline void intrusive_ptr_release(ObjectState *ptr) {
    if (--ptr->m_refCount == 0) {
        delete ptr;
    }
}

inline void intrusive_ptr_add_ref(const ObjectState *ptr) {
    ++ptr->m_refCount;
}

inline void intrusive_ptr_release(const ObjectState *ptr) {
    if (--ptr->m_refCount == 0) {
        delete ptr;
    }
}

struct ObjectStatePtrHash {
    size_t operator()(const ObjectStatePtr &x) const {
        return (size_t) x.get();
    }
    size_t operator()(const ObjectStateConstPtr &x) const {
        return (size_t) x.get();
    }
};

} // End klee namespace

#endif
