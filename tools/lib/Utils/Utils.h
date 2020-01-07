///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
}

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
