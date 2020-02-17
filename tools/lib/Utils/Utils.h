///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef TRANSLATOR_UTILS_H

#define TRANSLATOR_UTILS_H

#include <inttypes.h>
#include <iomanip>
#include <llvm/Support/raw_ostream.h>
#include <sstream>

#if 0
#include <llvm/ADT/DenseMapInfo.h>

namespace llvm {
  // Provide DenseMapInfo for uint64_t
  template<> struct DenseMapInfo<uint64_t> {
    static inline uint64_t getEmptyKey() { return ~0L; }
    static inline uint64_t getTombstoneKey() { return ~0L - 1L; }
    static unsigned getHashValue(const uint64_t& Val) {
      return (unsigned)(Val * 37L);
    }
    static bool isPod() { return true; }
    static bool isEqual(const uint64_t& LHS, const uint64_t& RHS) {
    return LHS == RHS;
    }
  };
}
#endif

namespace s2etools {
struct StartSizePair {
    uint64_t start, size;
    StartSizePair(uint64_t st, uint64_t sz) {
        start = st;
        size = sz;
    }
    bool operator<(const StartSizePair &p) const {
        return start + size <= p.start;
    }
};
} // namespace s2etools

struct hexval {
    const uint64_t value;
    const unsigned width;

    hexval(uint64_t v, unsigned w = 0) : value(v), width(w) {
    }
    hexval(const void *v, unsigned w = 0) : value((uint64_t) v), width(w) {
    }
};

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &out, const hexval &h) {
    std::stringstream ss;
    ss << "0x" << std::hex;
    if (h.width) {
        ss << std::setfill('0') << std::setw(h.width);
    }
    ss << h.value;
    out << ss.str();
    return out;
}

inline std::ostream &operator<<(std::ostream &out, const hexval &h) {
    out << "0x" << std::hex << (h.value);
    return out;
}

#define foreach2(_i, _b, _e) for (__typeof__(_b) _i = _b, _i##end = _e; _i != _i##end; ++_i)

#endif
