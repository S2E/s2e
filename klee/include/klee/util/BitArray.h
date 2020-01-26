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

#include <atomic>
#include <boost/intrusive_ptr.hpp>
#include <string.h>

namespace klee {

class BitArray;
typedef boost::intrusive_ptr<BitArray> BitArrayPtr;

// XXX would be nice not to have
// two allocations here for allocated
// BitArrays
class BitArray {
private:
    // XXX(s2e) for now we keep this first to access from C code
    // (yes, we do need to access if really fast)
    uint32_t *m_bits;
    std::atomic<unsigned> m_refCount;
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

    BitArray(unsigned size, bool value = false)
        : m_bits(new uint32_t[length(size)]), m_refCount(0), m_bitcount(size), m_setbitcount(value ? size : 0) {
        memset(m_bits, value ? 0xFF : 0, sizeof(*m_bits) * length(size));
    }

    BitArray(const BitArrayPtr &b) : m_bits(nullptr), m_refCount(0), m_bitcount(0), m_setbitcount(0) {
        m_bitcount = b->m_bitcount;
        m_setbitcount = b->m_setbitcount;
        m_bits = new uint32_t[length(m_bitcount)];
        memcpy(m_bits, b->m_bits, sizeof(*m_bits) * length(m_bitcount));
    }

public:
    static BitArrayPtr create(unsigned size, bool value = false) {
        return BitArrayPtr(new BitArray(size, value));
    }

    static BitArrayPtr create(const BitArrayPtr &b) {
        return BitArrayPtr(new BitArray(b));
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

    bool isAllZeros(unsigned size) const {
        return m_setbitcount == 0;
    }

    bool isAllOnes(unsigned size) const {
        return m_setbitcount == m_bitcount;
    }

    friend void intrusive_ptr_add_ref(BitArray *ptr);
    friend void intrusive_ptr_release(BitArray *ptr);
};

inline void intrusive_ptr_add_ref(BitArray *ptr) {
    ++ptr->m_refCount;
}

inline void intrusive_ptr_release(BitArray *ptr) {
    if (--ptr->m_refCount == 0) {
        delete ptr;
    }
}

} // namespace klee

#endif
