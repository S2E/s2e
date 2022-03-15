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

template <typename T> class BitArrayT {
private:
    // XXX(s2e) for now we keep this first to access from C code
    // (yes, we do need to access if really fast)
    T *m_bits;
    std::atomic<unsigned> m_refCount;
    unsigned m_bitcount;
    unsigned m_setbitcount;

    static const auto BITS = sizeof(*m_bits) * 8;
    static const auto BITSM1 = BITS - 1;

protected:
    static unsigned words(unsigned _bitcount) {
        return (_bitcount + BITSM1) / BITS;
    }

    BitArrayT(unsigned size, bool value = false)
        : m_bits(new T[words(size)]), m_refCount(0), m_bitcount(size), m_setbitcount(value ? size : 0) {
        memset(m_bits, value ? 0xFF : 0, sizeof(*m_bits) * words(size));
    }

    BitArrayT(const boost::intrusive_ptr<BitArrayT> &b)
        : m_bits(nullptr), m_refCount(0), m_bitcount(0), m_setbitcount(0) {
        m_bitcount = b->m_bitcount;
        m_setbitcount = b->m_setbitcount;
        m_bits = new T[words(m_bitcount)];
        memcpy(m_bits, b->m_bits, sizeof(*m_bits) * words(m_bitcount));
    }

    ~BitArrayT() {
        delete[] m_bits;
    }

public:
    static boost::intrusive_ptr<BitArrayT> create(unsigned size, bool value = false) {
        return boost::intrusive_ptr<BitArrayT>(new BitArrayT(size, value));
    }

    static boost::intrusive_ptr<BitArrayT> create(const boost::intrusive_ptr<BitArrayT> &b) {
        return boost::intrusive_ptr<BitArrayT>(new BitArrayT(b));
    }

    inline unsigned getBitCount() const {
        return m_bitcount;
    }

    inline bool get(unsigned idx) const {
        return (bool) ((m_bits[idx / BITS] >> (T) (idx & BITSM1)) & 1);
    }

    inline void set(unsigned idx) {
        if (!get(idx)) {
            ++m_setbitcount;
        }
        m_bits[idx / BITS] |= (T) 1 << (T) (idx & BITSM1);
    }

    inline void unset(unsigned idx) {
        if (get(idx)) {
            --m_setbitcount;
        }
        m_bits[idx / BITS] &= ~((T) 1 << (T) (idx & BITSM1));
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

    static inline int ctz64(uint64_t val) {
        return val ? __builtin_ctzll(val) : 64;
    }

    static inline int ctz32(uint32_t val) {
        return val ? __builtin_ctz(val) : 32;
    }

    static inline int ctz(T val) {
        if (sizeof(T) == sizeof(uint32_t)) {
            return ctz32(val);
        } else if (sizeof(T) == sizeof(uint64_t)) {
            return ctz64(val);
        } else {
            abort();
        }
    }

    bool findFirstSet(unsigned &index) const {
        auto nwords = words(m_bitcount);
        for (auto i = 0u; i < nwords; ++i) {
            if (!m_bits[i]) {
                continue;
            } else {
                auto firstBitSet = ctz(m_bits[i]) + 1;
                assert(firstBitSet);
                index = i * BITS + firstBitSet - 1;
                assert(get(index));
                return true;
            }
        }

        return false;
    }

    INTRUSIVE_PTR_FRIENDS(BitArrayT)
};

using BitArray = BitArrayT<uint64_t>;
using BitArrayPtr = boost::intrusive_ptr<BitArray>;

INTRUSIVE_PTR_ADD_REL(BitArrayT<uint64_t>)
INTRUSIVE_PTR_ADD_REL(BitArrayT<uint32_t>)

} // namespace klee

#endif
