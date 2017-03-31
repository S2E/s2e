//===-- BitArray.h ----------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_UTIL_BITARRAY_H
#define KLEE_UTIL_BITARRAY_H

namespace klee {

// XXX would be nice not to have
// two allocations here for allocated
// BitArrays
class BitArray {
private:
    // XXX(s2e) for now we keep this first to access from C code
    // (yes, we do need to access if really fast)
    uint32_t *m_bits;
    unsigned m_refcount;
    unsigned m_bitcount;
    unsigned m_setbitcount;

protected:
    static uint32_t length(unsigned _size) {
        return (_size + 31) / 32;
    }

    unsigned popcount_4(uint32_t x) const {
        int count;
        for (count = 0; x; count++)
            x &= x - 1;
        return count;
    }

    unsigned computePopCount() const {
        unsigned acc = 0;
        unsigned len = m_bitcount / 32;
        for (unsigned i = 0; i < len; ++i) {
            acc += popcount_4(m_bits[i]);
        }
        if (m_bitcount % 32) {
            uint32_t mask = (1 << (m_bitcount & 0x1F)) - 1;
            acc += popcount_4(m_bits[len] & mask);
        }
        return acc;
    }

public:
    BitArray(unsigned size, bool value = false)
        : m_bits(new uint32_t[length(size)]), m_refcount(1), m_bitcount(size), m_setbitcount(value ? size : 0) {
        memset(m_bits, value ? 0xFF : 0, sizeof(*m_bits) * length(size));
    }

    BitArray(const BitArray &b, unsigned size)
        : m_bits(new uint32_t[length(size)]), m_refcount(1), m_bitcount(size), m_setbitcount(0) {
        memcpy(m_bits, b.m_bits, sizeof(*m_bits) * length(size));
        m_setbitcount = computePopCount();
    }

    ~BitArray() {
        delete[] m_bits;
    }

    inline unsigned getBitCount() const {
        return m_bitcount;
    }

    inline bool get(unsigned idx) const {
        return (bool) ((m_bits[idx / 32] >> (idx & 0x1F)) & 1);
    }

    inline void set(unsigned idx) {
        if (!(m_bits[idx / 32] & 1 << (idx & 0x1F))) {
            ++m_setbitcount;
        }
        m_bits[idx / 32] |= 1 << (idx & 0x1F);
    }

    inline void unset(unsigned idx) {
        if ((m_bits[idx / 32] & 1 << (idx & 0x1F))) {
            --m_setbitcount;
        }
        m_bits[idx / 32] &= ~(1 << (idx & 0x1F));
    }

    inline void set(unsigned idx, bool value) {
        if (value) {
            set(idx);
        } else {
            unset(idx);
        }
    }

    inline const uint32_t *getBits() const {
        return m_bits;
    }

    inline unsigned getPopCount() {
        return m_setbitcount;
    }

    inline void incref() {
        ++m_refcount;
    }

    inline void decref() {
        --m_refcount;
        if (m_refcount == 0) {
            delete this;
        }
    }

    bool isAllZeros(unsigned size) const {
        return m_setbitcount == 0;
    }

    bool isAllOnes(unsigned size) const {
        return m_setbitcount == m_bitcount;
    }
};

} // End klee namespace

#endif
