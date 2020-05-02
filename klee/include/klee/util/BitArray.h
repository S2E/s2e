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

#include <klee/util/PtrUtils.h>

namespace klee {

class BitArray;
typedef boost::intrusive_ptr<BitArray> BitArrayPtr;

class BitArray {
private:
    // XXX(s2e) for now we keep this first to access from C code
    // (yes, we do need to access if really fast)
    // TODO: make this uint64_t
    uint32_t *m_bits;
    std::atomic<unsigned> m_refCount;
    unsigned m_bitcount;
    unsigned m_setbitcount;

    static const auto BITS = sizeof(*m_bits) * 8;
    static const auto BITSM1 = BITS - 1;

protected:
    static uint32_t length(unsigned _size) {
        return (_size + BITSM1) / BITS;
    }

    unsigned popcount_4(uint32_t x) const {
        int count;
        for (count = 0; x; count++)
            x &= x - 1;
        return count;
    }

    unsigned computePopCount() const {
        unsigned acc = 0;
        unsigned len = m_bitcount / BITS;
        for (unsigned i = 0; i < len; ++i) {
            acc += popcount_4(m_bits[i]);
        }
        if (m_bitcount % BITS) {
            uint32_t mask = (1 << (m_bitcount & (BITS - 1))) - 1;
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
        return (bool) ((m_bits[idx / BITS] >> (idx & BITSM1)) & 1);
    }

    inline void set(unsigned idx) {
        if (!get(idx)) {
            ++m_setbitcount;
        }
        m_bits[idx / BITS] |= 1 << (idx & BITSM1);
    }

    inline void unset(unsigned idx) {
        if (get(idx)) {
            --m_setbitcount;
        }
        m_bits[idx / BITS] &= ~(1 << (idx & BITSM1));
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

    bool isAllZeros() const {
        return m_setbitcount == 0;
    }

    bool isAllOnes() const {
        return m_setbitcount == m_bitcount;
    }

    unsigned getSetBitCount() const {
        return m_setbitcount;
    }

    bool findFirstSet(unsigned &index) const {
        auto words = length(m_bitcount);
        for (auto i = 0u; i < words; ++i) {
            if (!m_bits[i]) {
                continue;
            } else {
                auto firstBitSet = ffs(m_bits[i]);
                assert(firstBitSet);
                index = i * BITS + firstBitSet - 1;
                assert(get(index));
                return true;
            }
        }

        return false;
    }

    INTRUSIVE_PTR_FRIENDS(BitArray)
};

INTRUSIVE_PTR_ADD_REL(BitArray)

} // namespace klee

#endif
