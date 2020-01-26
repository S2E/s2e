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

#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Value.h>
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include <cassert>
#include <iostream>
#include <sstream>

using namespace llvm;

namespace klee {

ObjectState::ObjectState() {
}

ObjectState::ObjectState(uint64_t address, uint64_t size, bool fixed)
    : m_copyOnWriteOwner(0), m_refCount(0), m_address(address), m_size(size), m_fixed(fixed), m_splittable(false),
      m_readOnly(false), m_notifyOnConcretenessChange(false), m_isMemoryPage(false), m_isSharedConcrete(false),
      m_bufferOffset(0), m_updates(nullptr) {

    if (!m_fixed) {
        if (m_address) {
            abort();
        }

        m_fixedBuffer = std::shared_ptr<uint8_t>(new uint8_t[size], std::default_delete<uint8_t[]>());
        m_address = (uint64_t) m_fixedBuffer.get();
    }

    memset(m_fastConcreteBuffer, 0, sizeof(m_fastConcreteBuffer));
    if (m_size > FAST_CONCRETE_BUFFER_SIZE) {
        this->m_concreteBuffer = ConcreteBuffer::create(size);
    }
}

ObjectState::ObjectState(const ObjectState &os) {
    assert(!os.m_readOnly && "no need to copy read only object?");
    assert(!os.m_concreteMask || (os.m_size == os.m_concreteMask->getBitCount()));

    this->m_concreteMask = os.m_concreteMask ? BitArray::create(os.m_concreteMask) : nullptr;
    this->m_copyOnWriteOwner = os.m_copyOnWriteOwner;
    this->m_refCount = 0;
    this->m_address = os.m_address;
    this->m_size = os.m_size;
    this->m_name = os.m_name;
    this->m_fixed = os.m_fixed;
    this->m_fixedBuffer = os.m_fixedBuffer;
    this->m_splittable = os.m_splittable;
    this->m_readOnly = os.m_readOnly;
    this->m_notifyOnConcretenessChange = os.m_notifyOnConcretenessChange;
    this->m_isMemoryPage = os.m_isMemoryPage;
    this->m_isSharedConcrete = os.m_isSharedConcrete;

    this->m_concreteBuffer = nullptr;
    if (os.m_concreteBuffer) {
        this->m_concreteBuffer = ConcreteBuffer::create(os.m_concreteBuffer);
    }
    memcpy(this->m_fastConcreteBuffer, os.m_fastConcreteBuffer, sizeof(m_fastConcreteBuffer));
    this->m_bufferOffset = os.m_bufferOffset;
    this->m_flushMask = os.m_flushMask ? BitArray::create(os.m_flushMask) : nullptr;
    this->m_knownSymbolics = os.m_knownSymbolics;
    this->m_updates = os.m_updates ? UpdateList::create(os.m_updates->getRoot(), os.m_updates->getHead()) : nullptr;
}

ObjectState::~ObjectState() {
}

ObjectStatePtr ObjectState::allocate(uint64_t address, uint64_t size, bool isFixed) {

    if (size > 10 * 1024 * 1024) {
        klee_warning_once(0, "failing large alloc: %u bytes", (unsigned) size);
        return nullptr;
    }

    return ObjectStatePtr(new ObjectState(address, size, isFixed));
}

/***/

ObjectStatePtr ObjectState::split(unsigned offset, unsigned newSize) const {
    assert(m_splittable);
    assert(newSize <= m_size);
    assert(offset + newSize <= m_size);
    assert(m_flushMask == nullptr);
    assert(!m_updates || m_updates->getSize() == 0);
    assert(m_readOnly == false);

    auto ret = new ObjectState();

    ret->m_concreteMask = m_concreteMask;
    ret->m_copyOnWriteOwner = m_copyOnWriteOwner;
    ret->m_refCount = 0;
    ret->m_address = m_address + offset;
    ret->m_size = newSize;
    ret->m_name = m_name;
    ret->m_fixed = m_fixed;
    ret->m_fixedBuffer = m_fixedBuffer;
    ret->m_splittable = false;
    ret->m_readOnly = m_readOnly;
    ret->m_notifyOnConcretenessChange = m_notifyOnConcretenessChange;
    ret->m_isMemoryPage = m_isMemoryPage;
    ret->m_isSharedConcrete = m_isSharedConcrete;
    ret->m_concreteBuffer = m_concreteBuffer;
    memcpy(ret->m_fastConcreteBuffer, m_fastConcreteBuffer, sizeof(m_fastConcreteBuffer));
    ret->m_bufferOffset = offset;
    ret->m_flushMask = m_flushMask;

    if (m_knownSymbolics.size() > 0) {
        ret->m_knownSymbolics.resize(newSize);
        for (unsigned i = 0; i < newSize; i++) {
            ret->m_knownSymbolics[i] = m_knownSymbolics[i + offset];
        }
    }

    ret->m_updates = nullptr;

    return ObjectStatePtr(ret);
}

void ObjectState::initializeConcreteMask() {
    if (!m_concreteMask) {
        m_concreteMask = BitArray::create(m_size, true);
    }
}

ObjectStatePtr ObjectState::copy(const BitArrayPtr &_concreteMask, const ConcreteBufferPtr &_concreteStore) const {
    ObjectState *ret = new ObjectState(*this);

    ret->m_concreteMask = _concreteMask;
    ret->m_concreteBuffer = _concreteStore;

    return ObjectStatePtr(ret);
}

/***/

const UpdateListPtr &ObjectState::getUpdates() const {
    if (!m_updates) {
        m_updates = UpdateList::create(nullptr, nullptr);
    }

    if (m_updates->getRoot()) {
        return m_updates;
    }

    // Constant arrays are created lazily.

    // Collect the list of writes, with the oldest writes first.

    // FIXME: We should be able to do this more efficiently, we just need to be
    // careful to get the interaction with the cache right. In particular we
    // should avoid creating UpdateNode instances we never use.
    unsigned NumWrites = m_updates->getHead() ? m_updates->getHead()->getSize() : 0;
    std::vector<std::pair<ref<Expr>, ref<Expr>>> Writes(NumWrites);
    auto un = m_updates->getHead();
    for (unsigned i = NumWrites; i != 0; un = un->getNext()) {
        --i;
        Writes[i] = std::make_pair(un->getIndex(), un->getValue());
    }

    std::vector<ref<ConstantExpr>> Contents(m_size);

    // Initialize to zeros.
    for (unsigned i = 0, e = m_size; i != e; ++i) {
        Contents[i] = ConstantExpr::create(0, Expr::Int8);
    }

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
    auto array = Array::create("const_arr" + llvm::utostr(++id), m_size, &Contents[0], &Contents[0] + Contents.size());
    m_updates = UpdateList::create(array, 0);

    // Apply the remaining (non-constant) writes.
    for (; Begin != End; ++Begin) {
        m_updates->extend(Writes[Begin].first, Writes[Begin].second);
    }

    return m_updates;
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
    *size_r = m_size;
}

void ObjectState::flushRangeForRead(unsigned rangeBase, unsigned rangeSize) const {
    if (!m_flushMask) {
        m_flushMask = BitArray::create(m_size, true);
    }

    for (unsigned offset = rangeBase; offset < rangeBase + rangeSize; offset++) {
        if (!isByteFlushed(offset)) {
            if (isByteConcrete(offset)) {
                auto byte = getConcreteBuffer(true)[offset];
                getUpdates()->extend(ConstantExpr::create(offset, Expr::Int32), ConstantExpr::create(byte, Expr::Int8));
            } else {
                assert(isByteKnownSymbolic(offset) && "invalid bit set in flushMask");
                getUpdates()->extend(ConstantExpr::create(offset, Expr::Int32), m_knownSymbolics[offset]);
            }

            m_flushMask->unset(offset);
        }
    }
}

void ObjectState::flushRangeForWrite(unsigned rangeBase, unsigned rangeSize) {
    if (!m_flushMask) {
        m_flushMask = BitArray::create(m_size, true);
    }

    for (unsigned offset = rangeBase; offset < rangeBase + rangeSize; offset++) {
        if (!isByteFlushed(offset)) {
            if (isByteConcrete(offset)) {
                auto byte = getConcreteBuffer(true)[offset];
                getUpdates()->extend(ConstantExpr::create(offset, Expr::Int32), ConstantExpr::create(byte, Expr::Int8));
                markByteSymbolic(offset);
            } else {
                assert(isByteKnownSymbolic(offset) && "invalid bit set in flushMask");
                getUpdates()->extend(ConstantExpr::create(offset, Expr::Int32), m_knownSymbolics[offset]);
                setKnownSymbolic(offset, 0);
            }

            m_flushMask->unset(offset);
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
    return !m_concreteMask || m_concreteMask->isAllOnes(m_size);
}

const uint8_t *ObjectState::getConcreteBuffer(bool allowSymbolic) const {
    if (!allowSymbolic && !isAllConcrete()) {
        return NULL;
    }

    if (m_size <= FAST_CONCRETE_BUFFER_SIZE) {
        assert(m_bufferOffset == 0);
        return &m_fastConcreteBuffer[0];
    } else {
        return m_concreteBuffer->get() + m_bufferOffset;
    }
}

uint8_t *ObjectState::getConcreteBuffer(bool allowSymbolic) {
    if (!allowSymbolic && !isAllConcrete()) {
        return NULL;
    }

    if (m_size <= FAST_CONCRETE_BUFFER_SIZE) {
        assert(m_bufferOffset == 0);
        return &m_fastConcreteBuffer[0];
    } else {
        return m_concreteBuffer->get() + m_bufferOffset;
    }
}

void ObjectState::markByteSymbolic(unsigned offset) {
    if (!m_concreteMask) {
        m_concreteMask = BitArray::create(m_size, true);
    }
    m_concreteMask->unset(m_bufferOffset + offset);
}

void ObjectState::markByteFlushed(unsigned offset) {
    if (!m_flushMask) {
        m_flushMask = BitArray::create(m_size, false);
    } else {
        m_flushMask->unset(offset);
    }
}

inline void ObjectState::setKnownSymbolic(unsigned offset, const ref<Expr> &value) {
    if (m_knownSymbolics.size() > 0) {
        m_knownSymbolics[offset] = value;
    } else {
        if (!value.isNull()) {
            m_knownSymbolics.resize(m_size);
            m_knownSymbolics[offset] = value;
        }
    }
}

/***/

ref<Expr> ObjectState::read8(unsigned offset) const {
    if (!isSharedConcrete()) {
        if (isByteConcrete(offset)) {
            auto byte = getConcreteBuffer(true)[offset];
            return ConstantExpr::create(byte, Expr::Int8);
        } else if (isByteKnownSymbolic(offset)) {
            return m_knownSymbolics[offset];
        } else {
            assert(isByteFlushed(offset) && "unflushed byte without cache value");
            assert(offset < m_size);
            return ReadExpr::create(getUpdates(), ConstantExpr::create(offset, Expr::Int32));
        }
    } else {
        return ConstantExpr::create(((uint8_t *) m_address)[offset], Expr::Int8);
    }
}

ref<Expr> ObjectState::read8(ref<Expr> offset) const {
    assert(!isa<ConstantExpr>(offset) && "constant offset passed to symbolic read8");
    assert(!isSharedConcrete() && "read at non-constant offset for shared concrete object");
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
    if (!isSharedConcrete()) {
        auto byte = &getConcreteBuffer(true)[offset];
        *byte = value;
        setKnownSymbolic(offset, 0);

        markByteConcrete(offset);
        markByteUnflushed(offset);
    } else {
        ((uint8_t *) m_address)[offset] = value;
    }
}

void ObjectState::write8(unsigned offset, ref<Expr> value) {
    // can happen when ExtractExpr special cases
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(value)) {
        write8(offset, (uint8_t) CE->getZExtValue(8));
    } else {
        assert(!isSharedConcrete() && "write of non-constant value to shared concrete object");
        setKnownSymbolic(offset, value.get());

        markByteSymbolic(offset);
        markByteUnflushed(offset);
    }
}

void ObjectState::write8(ref<Expr> offset, ref<Expr> value) {
    assert(!isa<ConstantExpr>(offset) && "constant offset passed to symbolic write8");
    assert(!isSharedConcrete() && "write at non-constant offset for shared concrete object");
    unsigned base, size;
    fastRangeCheckOffset(offset, &base, &size);
    flushRangeForWrite(base, size);

    if (size > 4096) {
        klee_warning_once(0, "flushing %d bytes on read, may be slow and/or crash", size);
    }

    getUpdates()->extend(ZExtExpr::create(offset, Expr::Int32), value);
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
                    pabort("Invalid write size!");
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
} // namespace klee
