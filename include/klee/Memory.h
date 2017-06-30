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

namespace llvm {
class Value;
}

namespace klee {

class BitArray;
class MemoryManager;
class Solver;

class InitialStateAllocator {
private:
    uintptr_t m_bufferBase;
    uintptr_t m_bufferTop;
    uintptr_t m_bufferSize;
    uintptr_t m_pointer;

    bool m_enabled;

    static InitialStateAllocator *s_allocator;

    InitialStateAllocator(uint64_t size) {
        m_bufferSize = size;
        m_bufferBase = (uintptr_t) malloc(size);
        if (!m_bufferSize) {
            throw std::bad_alloc();
        }
        m_bufferTop = m_bufferBase + size;
        m_pointer = m_bufferBase;
        m_enabled = true;
    }

    static bool initializeInternal(uint64_t totalSize) {
        if (s_allocator) {
            return false;
        }

        s_allocator = new InitialStateAllocator(totalSize);
        return true;
    }

public:
    static bool initialize(uint64_t pageCount);

    void activate(bool status) {
        m_enabled = status;
    }

    inline bool enabled() {
        return m_enabled;
    }

    static inline InitialStateAllocator *get() {
        return s_allocator;
    }

    inline void *allocate(size_t size) {
        assert(s_allocator);
        uintptr_t ret = 0;
        if (m_pointer + size < m_bufferTop) {
            ret = m_pointer;
            m_pointer += size;
        }
        return (void *) ret;
    }

    inline bool ours(void *ptr) {
        assert(s_allocator);
        uintptr_t ptr2 = (uintptr_t) ptr;
        return ptr2 >= m_bufferBase && ptr2 < m_bufferTop;
    }

    static inline void *alloc_new(size_t size) {
        InitialStateAllocator *alloc = get();
        void *ret = NULL;

        if (alloc && alloc->enabled()) {
            ret = alloc->allocate(size);
        }

        if (!ret) {
            ret = malloc(size);
            if (!ret) {
                throw std::bad_alloc();
            }
        }

        return ret;
    }

    static inline void alloc_delete(void *ptr) {
        InitialStateAllocator *alloc = get();
        if (alloc && alloc->ours(ptr)) {
            return;
        } else {
            free(ptr);
        }
    }
};

class MemoryObject {
private:
    static int counter;

public:
    unsigned id;
    uint64_t address;

    /// size in bytes
    unsigned size;
    std::string name;

    bool isLocal;
    bool isGlobal;
    bool isFixed;

    /// true if created by us.
    bool fake_object;

    /// User-specified object will not be concretized/restored
    /// when switching to/from concrete execution. That is,
    /// copy(In|Out)Concretes ignores this object.
    bool isUserSpecified;

    /// True if this object should always be accessed directly
    /// by its address (i.e., baypassing all ObjectStates).
    /// This means that the object will always contain concrete
    /// values and its conctent will be shared across all states
    /// (unless explicitly saved/restored on state switches -
    /// ObjectState will still be allocated for this purpose).
    bool isSharedConcrete;

    /// True if the object value can be ignored in local consistency
    bool isValueIgnored;

    /// True if can be split into smaller objects
    bool isSplittable;

    /// True if this is an S2E physical memory page (or subpage)
    bool isMemoryPage;

    /// True to get notifications when the object becomes fully concrete
    /// or at least one byte becomes symbolic.
    /// If the object is split into multiple ones, the event is triggered
    /// when the entire group of objects gets the property.
    bool doNotifyOnConcretenessChange;

    /// "Location" for which this memory object was allocated. This
    /// should be either the allocating instruction or the global object
    /// it was allocated for (or whatever else makes sense).
    const llvm::Value *allocSite;

    /// A list of boolean expressions the user has requested be true of
    /// a counterexample. Mutable since we play a little fast and loose
    /// with allowing it to be added to during execution (although
    /// should sensibly be only at creation time).
    mutable std::vector<ref<Expr>> cexPreferences;

    // DO NOT IMPLEMENT
    MemoryObject(const MemoryObject &b);
    MemoryObject &operator=(const MemoryObject &b);

public:
    // XXX this is just a temp hack, should be removed
    explicit MemoryObject(uint64_t _address)
        : id(counter++), address(_address), size(0), isFixed(true), isSplittable(false),
          doNotifyOnConcretenessChange(false), allocSite(0) {
    }

    MemoryObject(uint64_t _address, unsigned _size, bool _isLocal, bool _isGlobal, bool _isFixed,
                 const llvm::Value *_allocSite)
        : id(counter++), address(_address), size(_size), name("unnamed"), isLocal(_isLocal), isGlobal(_isGlobal),
          isFixed(_isFixed), fake_object(false), isUserSpecified(false), isSharedConcrete(false), isSplittable(false),
          isMemoryPage(false), doNotifyOnConcretenessChange(false), allocSite(_allocSite) {
    }

    ~MemoryObject();

    /// Get an identifying string for this allocation.
    void getAllocInfo(std::string &result) const;

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

    void *operator new(size_t size) {
        return InitialStateAllocator::alloc_new(size);
    }

    void operator delete(void *ptr) {
        return InitialStateAllocator::alloc_delete(ptr);
    }

    // Split the current object at specified offsets
    void split(std::vector<MemoryObject *> &objects, const std::vector<unsigned> &offsets) const;
};

class ObjectState {
public:
    static uint64_t count;
    static uint64_t ssize;

private:
    // XXX(s2e) for now we keep this first to access from C code
    // (yes, we do need to access if really fast)
    BitArray *concreteMask;

    friend class AddressSpace;
    template <typename U> friend class AddressSpaceBase;
    unsigned copyOnWriteOwner; // exclusively for AddressSpace

    friend class ObjectHolder;
    unsigned refCount;

    const MemoryObject *object;

    // XXX: made it public for fast access
    ConcreteBuffer *concreteStore;

    // If the store is shared between object states,
    // indicate the offset of our region
    unsigned storeOffset;

    // XXX cleanup name of flushMask (its backwards or something)
    // mutable because may need flushed during read of const
    mutable BitArray *flushMask;

    ref<Expr> *knownSymbolics;

    // mutable because we may need flush during read of const
    mutable UpdateList updates;

public:
    unsigned size;

    bool readOnly;

private:
    ObjectState();

    // For AddressSpace
    ConcreteBuffer *getConcreteBufferAs() {
        return concreteStore;
    }

public:
    /// Create a new object state for the given memory object with concrete
    /// contents. The initial contents are undefined, it is the callers
    /// responsibility to initialize the object contents appropriately.
    ObjectState(const MemoryObject *mo);

    /// Create a new object state for the given memory object with symbolic
    /// contents.
    ObjectState(const MemoryObject *mo, const Array *array);

    ObjectState(const ObjectState &os);
    ~ObjectState();

    inline const MemoryObject *getObject() const {
        return object;
    }

    void setReadOnly(bool ro) {
        readOnly = ro;
    }

    // make contents all concrete and zero
    void initializeToZero();
    // make contents all concrete and random
    void initializeToRandom();

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
        if (!concreteMask)
            return true;

        unsigned size = Expr::getMinBytesForWidth(width);
        for (unsigned i = 0; i < size; ++i) {
            if (!isByteConcrete(offset + i))
                return false;
        }
        return true;
    }

    const uint8_t *getConcreteStore(bool allowSymbolic = false) const;
    uint8_t *getConcreteStore(bool allowSymolic = false);

    const ConcreteBuffer *getConcreteBuffer() const {
        return concreteStore;
    }

    const BitArray *getConcreteMask() const {
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

    void replaceConcreteBuffer(ConcreteBuffer *buffer) {
        concreteStore = buffer;
    }

private:
    const UpdateList &getUpdates() const;

    void makeConcrete();

    void makeSymbolic();

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
        return knownSymbolics && knownSymbolics[offset].get();
    }

    inline void markByteConcrete(unsigned offset) {
        if (concreteMask)
            concreteMask->set(storeOffset + offset);
    }

    void markByteSymbolic(unsigned offset);

    void markByteFlushed(unsigned offset);

    void markByteUnflushed(unsigned offset) {
        if (flushMask)
            flushMask->set(offset);
    }

    void setKnownSymbolic(unsigned offset, Expr *value);

    void print();

    ObjectState *getCopy(BitArray *_concreteMask, ConcreteBuffer *_concreteStore) const;

public:
    void *operator new(size_t size) {
        return InitialStateAllocator::alloc_new(size);
    }

    void operator delete(void *ptr) {
        return InitialStateAllocator::alloc_delete(ptr);
    }
};

} // End klee namespace

#endif
